/*
 * AFWall root DNS daemon.
 *
 * This daemon is intentionally independent from the Android application
 * lifecycle. The app writes config and supervises the process, while this
 * binary handles DNS requests, rule lookups, cache, stats, and control socket
 * commands as a root-owned background service.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <regex.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define MAX_PACKET 4096
#define MAX_DOMAIN 256
#define MAX_RULES 32768
#define MAX_REGEX 128
#define MAX_TEMP_RULES 1024
#define MAX_UPSTREAMS 8
#define CACHE_SIZE 1024
#define LOG_RING 256
#define DEFAULT_PORT 5354
#define DEFAULT_TIMEOUT_MS 2500

typedef enum {
    DECISION_ALLOW = 0,
    DECISION_BLOCK = 1
} decision_t;

typedef struct {
    char value[MAX_DOMAIN];
} string_rule_t;

typedef struct {
    regex_t compiled;
    char pattern[MAX_DOMAIN];
    bool valid;
} regex_rule_t;

typedef struct {
    char value[MAX_DOMAIN];
    uint64_t expires_at;
} temp_rule_t;

typedef struct {
    char host[128];
    int port;
} upstream_t;

typedef struct {
    int listen_port;
    int strict_mode;
    int fail_open;
    int timeout_ms;
    char control_socket[256];
    char log_file[256];
    char pid_file[256];
    upstream_t upstreams[MAX_UPSTREAMS];
    int upstream_count;
    string_rule_t exact_allow[MAX_RULES];
    string_rule_t suffix_allow[MAX_RULES];
    string_rule_t exact_block[MAX_RULES];
    string_rule_t suffix_block[MAX_RULES];
    int exact_allow_count;
    int suffix_allow_count;
    int exact_block_count;
    int suffix_block_count;
    regex_rule_t regex_allow[MAX_REGEX];
    regex_rule_t regex_block[MAX_REGEX];
    int regex_allow_count;
    int regex_block_count;
    temp_rule_t temp_allow[MAX_TEMP_RULES];
    temp_rule_t temp_block[MAX_TEMP_RULES];
    int temp_allow_count;
    int temp_block_count;
    uint64_t generation;
} config_t;

typedef struct {
    uint64_t queries;
    uint64_t allowed;
    uint64_t blocked;
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t cache_stores;
    uint64_t cache_expired;
    uint64_t cache_evictions;
    uint64_t udp_queries;
    uint64_t tcp_queries;
    uint64_t invalid_queries;
    uint64_t fail_open_drops;
    uint64_t fail_closed_blocks;
    uint64_t upstream_requests;
    uint64_t upstream_successes;
    uint64_t upstream_failures;
    uint64_t total_latency_ms;
    uint64_t upstream_latency_ms;
    uint64_t max_latency_ms;
    uint64_t reloads;
    uint64_t start_time;
} stats_t;

typedef struct {
    uint64_t seq;
    char domain[MAX_DOMAIN];
    char action[16];
    int latency_ms;
    uint64_t timestamp;
} log_entry_t;

typedef struct {
    char domain[MAX_DOMAIN];
    uint16_t qtype;
    uint8_t response[MAX_PACKET];
    size_t response_len;
    time_t expires_at;
    uint32_t hash;
    bool used;
} cache_entry_t;

static volatile sig_atomic_t g_running = 1;
static config_t g_cfg;
static stats_t g_stats;
static log_entry_t g_logs[LOG_RING];
static int g_log_pos = 0;
static uint64_t g_log_seq = 0;
static uint64_t g_log_flushed_seq = 0;
static cache_entry_t g_cache[CACHE_SIZE];
static char g_config_path[256];

static uint64_t now_seconds(void) {
    return (uint64_t) time(NULL);
}

static int elapsed_ms(const struct timeval *start, const struct timeval *end) {
    long seconds = end->tv_sec - start->tv_sec;
    long micros = end->tv_usec - start->tv_usec;
    return (int) ((seconds * 1000L) + (micros / 1000L));
}

static void trim(char *s) {
    size_t len;
    char *p = s;
    while (*p && isspace((unsigned char) *p)) {
        p++;
    }
    if (p != s) {
        memmove(s, p, strlen(p) + 1);
    }
    len = strlen(s);
    while (len > 0 && isspace((unsigned char) s[len - 1])) {
        s[len - 1] = '\0';
        len--;
    }
}

static void lower_ascii(char *s) {
    while (*s) {
        *s = (char) tolower((unsigned char) *s);
        s++;
    }
}

static void safe_copy(char *dst, size_t dst_len, const char *src) {
    if (dst_len == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    strncpy(dst, src, dst_len - 1);
    dst[dst_len - 1] = '\0';
}

static uint32_t hash_domain(const char *domain, uint16_t qtype) {
    uint32_t h = 2166136261u;
    const unsigned char *p = (const unsigned char *) domain;
    while (*p) {
        h ^= *p++;
        h *= 16777619u;
    }
    h ^= qtype & 0xffu;
    h *= 16777619u;
    h ^= (qtype >> 8) & 0xffu;
    h *= 16777619u;
    return h;
}

static uint64_t div_u64(uint64_t numerator, uint64_t denominator) {
    return denominator == 0 ? 0 : numerator / denominator;
}

static void record_query_latency(int latency_ms) {
    uint64_t latency;
    if (latency_ms < 0) {
        latency_ms = 0;
    }
    latency = (uint64_t) latency_ms;
    g_stats.total_latency_ms += latency;
    if (latency > g_stats.max_latency_ms) {
        g_stats.max_latency_ms = latency;
    }
}

static int cache_entry_count(void) {
    int count = 0;
    int i;
    time_t now = time(NULL);
    for (i = 0; i < CACHE_SIZE; i++) {
        if (g_cache[i].used && g_cache[i].expires_at > now) {
            count++;
        }
    }
    return count;
}

static void add_log(const char *domain, const char *action, int latency_ms) {
    log_entry_t *entry = &g_logs[g_log_pos % LOG_RING];
    entry->seq = ++g_log_seq;
    safe_copy(entry->domain, sizeof(entry->domain), domain);
    safe_copy(entry->action, sizeof(entry->action), action);
    entry->latency_ms = latency_ms;
    entry->timestamp = now_seconds();
    g_log_pos = (g_log_pos + 1) % LOG_RING;
}

static void flush_logs(void) {
    FILE *fp;
    uint64_t first_seq;
    uint64_t seq;
    int i;

    if (g_cfg.log_file[0] == '\0' || g_log_flushed_seq == g_log_seq) {
        return;
    }

    first_seq = g_log_flushed_seq + 1;
    if (g_log_seq >= LOG_RING && first_seq < g_log_seq - LOG_RING + 1) {
        first_seq = g_log_seq - LOG_RING + 1;
    }

    fp = fopen(g_cfg.log_file, "a");
    if (fp == NULL) {
        return;
    }

    for (seq = first_seq; seq <= g_log_seq; seq++) {
        for (i = 0; i < LOG_RING; i++) {
            const log_entry_t *entry = &g_logs[i];
            if (entry->seq == seq) {
                fprintf(fp, "%llu %s %s %dms\n",
                        (unsigned long long) entry->timestamp,
                        entry->action,
                        entry->domain,
                        entry->latency_ms);
                break;
            }
        }
    }
    fclose(fp);
    g_log_flushed_seq = g_log_seq;
}

static void free_regex_rules(config_t *cfg) {
    int i;
    for (i = 0; i < cfg->regex_allow_count; i++) {
        if (cfg->regex_allow[i].valid) {
            regfree(&cfg->regex_allow[i].compiled);
            cfg->regex_allow[i].valid = false;
        }
    }
    for (i = 0; i < cfg->regex_block_count; i++) {
        if (cfg->regex_block[i].valid) {
            regfree(&cfg->regex_block[i].compiled);
            cfg->regex_block[i].valid = false;
        }
    }
}

static bool add_string_rule(string_rule_t *rules, int *count, const char *value) {
    if (*count >= MAX_RULES || value == NULL || value[0] == '\0') {
        return false;
    }
    safe_copy(rules[*count].value, sizeof(rules[*count].value), value);
    lower_ascii(rules[*count].value);
    (*count)++;
    return true;
}

static bool valid_domain_rule(const char *value) {
    const char *p = value;
    size_t label_len = 0;
    bool dot_seen = false;
    if (value == NULL || value[0] == '\0' || strlen(value) >= MAX_DOMAIN) {
        return false;
    }
    while (*p) {
        unsigned char c = (unsigned char) *p;
        if (c == '.') {
            if (label_len == 0 || label_len > 63) {
                return false;
            }
            dot_seen = true;
            label_len = 0;
        } else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
            label_len++;
        } else {
            return false;
        }
        p++;
    }
    return dot_seen && label_len > 0 && label_len <= 63;
}

static bool add_temp_rule(temp_rule_t *rules, int *count, const char *value) {
    char line[512];
    char *sep;
    char *domain;
    char *expires;
    uint64_t expires_at;
    if (*count >= MAX_TEMP_RULES || value == NULL || value[0] == '\0') {
        return false;
    }
    safe_copy(line, sizeof(line), value);
    sep = strchr(line, '|');
    if (sep == NULL) {
        sep = strchr(line, ' ');
    }
    if (sep == NULL) {
        return false;
    }
    *sep = '\0';
    domain = line;
    expires = sep + 1;
    trim(domain);
    trim(expires);
    lower_ascii(domain);
    expires_at = (uint64_t) strtoull(expires, NULL, 10);
    if (!valid_domain_rule(domain) || expires_at <= now_seconds()) {
        return false;
    }
    safe_copy(rules[*count].value, sizeof(rules[*count].value), domain);
    rules[*count].expires_at = expires_at;
    (*count)++;
    return true;
}

static bool add_regex_rule(regex_rule_t *rules, int *count, const char *value) {
    regex_rule_t *rule;
    if (*count >= MAX_REGEX || value == NULL || value[0] == '\0') {
        return false;
    }
    rule = &rules[*count];
    memset(rule, 0, sizeof(*rule));
    safe_copy(rule->pattern, sizeof(rule->pattern), value);
    if (regcomp(&rule->compiled, value, REG_EXTENDED | REG_NOSUB | REG_ICASE) != 0) {
        return false;
    }
    rule->valid = true;
    (*count)++;
    return true;
}

static bool exact_match(const string_rule_t *rules, int count, const char *domain) {
    int i;
    for (i = 0; i < count; i++) {
        if (strcmp(rules[i].value, domain) == 0) {
            return true;
        }
    }
    return false;
}

static bool temp_match(const temp_rule_t *rules, int count, const char *domain, uint64_t now) {
    int i;
    for (i = 0; i < count; i++) {
        if (rules[i].expires_at > now && strcmp(rules[i].value, domain) == 0) {
            return true;
        }
    }
    return false;
}

static bool suffix_match(const string_rule_t *rules, int count, const char *domain) {
    int i;
    size_t domain_len = strlen(domain);
    for (i = 0; i < count; i++) {
        const char *suffix = rules[i].value;
        size_t suffix_len = strlen(suffix);
        if (suffix_len == 0 || suffix_len > domain_len) {
            continue;
        }
        if (strcmp(domain + domain_len - suffix_len, suffix) == 0) {
            if (suffix_len == domain_len || domain[domain_len - suffix_len - 1] == '.') {
                return true;
            }
        }
    }
    return false;
}

static bool regex_match_rules(const regex_rule_t *rules, int count, const char *domain) {
    int i;
    for (i = 0; i < count; i++) {
        if (rules[i].valid && regexec(&rules[i].compiled, domain, 0, NULL, 0) == 0) {
            return true;
        }
    }
    return false;
}

static decision_t evaluate_domain(const config_t *cfg, const char *domain, const char **reason) {
    uint64_t now = now_seconds();
    bool temp_allow = temp_match(cfg->temp_allow, cfg->temp_allow_count, domain, now);
    bool exact_allow = exact_match(cfg->exact_allow, cfg->exact_allow_count, domain);
    bool suffix_allow = suffix_match(cfg->suffix_allow, cfg->suffix_allow_count, domain);
    bool regex_allow = regex_match_rules(cfg->regex_allow, cfg->regex_allow_count, domain);
    bool block = false;

    if (temp_match(cfg->temp_block, cfg->temp_block_count, domain, now)) {
        *reason = "temp_block";
        block = true;
    } else if (exact_match(cfg->exact_block, cfg->exact_block_count, domain)) {
        *reason = "exact_block";
        block = true;
    } else if (suffix_match(cfg->suffix_block, cfg->suffix_block_count, domain)) {
        *reason = "suffix_block";
        block = true;
    } else if (regex_match_rules(cfg->regex_block, cfg->regex_block_count, domain)) {
        *reason = "regex_block";
        block = true;
    }

    if (block && cfg->strict_mode) {
        return DECISION_BLOCK;
    }
    if (temp_allow) {
        *reason = "temp_allow";
        return DECISION_ALLOW;
    }
    if (exact_allow) {
        *reason = "exact_allow";
        return DECISION_ALLOW;
    }
    if (suffix_allow) {
        *reason = "suffix_allow";
        return DECISION_ALLOW;
    }
    if (regex_allow) {
        *reason = "regex_allow";
        return DECISION_ALLOW;
    }
    if (block) {
        return DECISION_BLOCK;
    }
    *reason = "upstream";
    return DECISION_ALLOW;
}

static bool parse_qname(const uint8_t *packet, size_t len, char *domain, size_t domain_len, uint16_t *qtype) {
    size_t pos = 12;
    size_t out = 0;
    if (len < 12) {
        return false;
    }
    while (pos < len) {
        uint8_t label_len = packet[pos++];
        if (label_len == 0) {
            break;
        }
        if ((label_len & 0xc0u) != 0 || label_len > 63 || pos + label_len > len) {
            return false;
        }
        if (out != 0) {
            if (out + 1 >= domain_len) {
                return false;
            }
            domain[out++] = '.';
        }
        if (out + label_len >= domain_len) {
            return false;
        }
        memcpy(domain + out, packet + pos, label_len);
        out += label_len;
        pos += label_len;
    }
    if (pos + 4 > len || out == 0) {
        return false;
    }
    domain[out] = '\0';
    lower_ascii(domain);
    *qtype = (uint16_t) ((packet[pos] << 8) | packet[pos + 1]);
    return true;
}

static size_t build_block_response(const uint8_t *query, size_t query_len, uint8_t *out, size_t out_len) {
    size_t pos = 12;
    if (query_len < 12 || out_len < query_len) {
        return 0;
    }
    while (pos < query_len && query[pos] != 0) {
        uint8_t label_len = query[pos];
        if ((label_len & 0xc0u) != 0 || label_len > 63 || pos + label_len + 1 > query_len) {
            return 0;
        }
        pos += (size_t) label_len + 1;
    }
    if (pos + 5 > query_len) {
        return 0;
    }
    memcpy(out, query, pos + 5);
    out[2] = 0x81;
    out[3] = 0x83;
    out[6] = 0x00;
    out[7] = 0x00;
    out[8] = 0x00;
    out[9] = 0x00;
    out[10] = 0x00;
    out[11] = 0x00;
    return pos + 5;
}

static uint32_t read_u32(const uint8_t *p) {
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | p[3];
}

static uint16_t read_u16(const uint8_t *p) {
    return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

static size_t skip_name(const uint8_t *packet, size_t len, size_t pos) {
    while (pos < len) {
        uint8_t c = packet[pos++];
        if (c == 0) {
            return pos;
        }
        if ((c & 0xc0u) == 0xc0u) {
            return pos + 1 <= len ? pos + 1 : len + 1;
        }
        if ((c & 0xc0u) != 0 || pos + c > len) {
            return len + 1;
        }
        pos += c;
    }
    return len + 1;
}

static uint32_t extract_min_ttl(const uint8_t *packet, size_t len) {
    uint16_t qd;
    uint16_t an;
    size_t pos = 12;
    uint16_t i;
    uint32_t min_ttl = 60;
    if (len < 12) {
        return 0;
    }
    qd = read_u16(packet + 4);
    an = read_u16(packet + 6);
    for (i = 0; i < qd; i++) {
        pos = skip_name(packet, len, pos);
        if (pos + 4 > len) {
            return 0;
        }
        pos += 4;
    }
    if (an == 0) {
        return 30;
    }
    min_ttl = UINT32_MAX;
    for (i = 0; i < an; i++) {
        uint32_t ttl;
        uint16_t rdlen;
        pos = skip_name(packet, len, pos);
        if (pos + 10 > len) {
            return 30;
        }
        ttl = read_u32(packet + pos + 4);
        rdlen = read_u16(packet + pos + 8);
        if (ttl < min_ttl) {
            min_ttl = ttl;
        }
        pos += 10 + rdlen;
        if (pos > len) {
            return 30;
        }
    }
    if (min_ttl == UINT32_MAX || min_ttl == 0) {
        return 30;
    }
    if (min_ttl > 86400) {
        return 86400;
    }
    return min_ttl;
}

static bool cache_lookup(const char *domain, uint16_t qtype, const uint8_t *query, uint8_t *out, size_t *out_len) {
    uint32_t h = hash_domain(domain, qtype);
    uint32_t start = h % CACHE_SIZE;
    uint32_t i;
    time_t now = time(NULL);
    for (i = 0; i < 8; i++) {
        cache_entry_t *entry = &g_cache[(start + i) % CACHE_SIZE];
        if (!entry->used) {
            continue;
        }
        if (entry->hash == h && entry->qtype == qtype && strcmp(entry->domain, domain) == 0) {
            if (entry->expires_at <= now) {
                entry->used = false;
                g_stats.cache_expired++;
                continue;
            }
            memcpy(out, entry->response, entry->response_len);
            out[0] = query[0];
            out[1] = query[1];
            *out_len = entry->response_len;
            return true;
        }
    }
    return false;
}

static bool response_cacheable(const uint8_t *response, size_t response_len) {
    uint16_t flags;
    uint16_t rcode;
    if (response_len < 12) {
        return false;
    }
    flags = read_u16(response + 2);
    rcode = flags & 0x000fu;
    if ((flags & 0x8000u) == 0) {
        return false;
    }
    return rcode == 0 || rcode == 3;
}

static void cache_store(const char *domain, uint16_t qtype, const uint8_t *response, size_t response_len) {
    uint32_t h;
    uint32_t slot;
    uint32_t ttl;
    cache_entry_t *entry;
    uint32_t i;
    time_t now = time(NULL);
    bool evicting = false;
    if (response_len < 12 || response_len > MAX_PACKET || !response_cacheable(response, response_len)) {
        return;
    }
    ttl = extract_min_ttl(response, response_len);
    if (ttl == 0) {
        return;
    }
    h = hash_domain(domain, qtype);
    slot = h % CACHE_SIZE;
    entry = NULL;
    for (i = 0; i < 8; i++) {
        cache_entry_t *candidate = &g_cache[(slot + i) % CACHE_SIZE];
        if (candidate->used && candidate->hash == h
                && candidate->qtype == qtype
                && strcmp(candidate->domain, domain) == 0) {
            entry = candidate;
            break;
        }
        if (!candidate->used || candidate->expires_at <= now) {
            if (candidate->used) {
                g_stats.cache_expired++;
            }
            entry = candidate;
            break;
        }
    }
    if (entry == NULL) {
        entry = &g_cache[slot];
        evicting = entry->used && entry->expires_at > now;
    }
    if (evicting) {
        g_stats.cache_evictions++;
    }
    memset(entry, 0, sizeof(*entry));
    safe_copy(entry->domain, sizeof(entry->domain), domain);
    entry->qtype = qtype;
    entry->hash = h;
    memcpy(entry->response, response, response_len);
    entry->response_len = response_len;
    entry->expires_at = now + ttl;
    entry->used = true;
    g_stats.cache_stores++;
}

static int connect_upstream(const upstream_t *upstream, int socktype, int timeout_ms) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *rp;
    char port[16];
    int fd = -1;
    snprintf(port, sizeof(port), "%d", upstream->port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    if (getaddrinfo(upstream->host, port, &hints, &res) != 0) {
        return -1;
    }
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        struct timeval timeout;
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static ssize_t forward_udp(const config_t *cfg, const uint8_t *query, size_t query_len, uint8_t *response, size_t response_len) {
    int i;
    for (i = 0; i < cfg->upstream_count; i++) {
        int fd = connect_upstream(&cfg->upstreams[i], SOCK_DGRAM, cfg->timeout_ms);
        ssize_t got;
        if (fd < 0) {
            continue;
        }
        if (send(fd, query, query_len, 0) < 0) {
            close(fd);
            continue;
        }
        got = recv(fd, response, response_len, 0);
        close(fd);
        if (got > 0) {
            return got;
        }
    }
    return -1;
}

static ssize_t forward_udp_probe(const config_t *cfg, const uint8_t *query, size_t query_len,
                                 uint8_t *response, size_t response_len, int *upstream_index) {
    int i;
    int timeout_ms = cfg->timeout_ms < 1000 ? cfg->timeout_ms : 1000;
    if (timeout_ms < 250) {
        timeout_ms = 250;
    }
    if (upstream_index != NULL) {
        *upstream_index = -1;
    }
    for (i = 0; i < cfg->upstream_count; i++) {
        int fd = connect_upstream(&cfg->upstreams[i], SOCK_DGRAM, timeout_ms);
        ssize_t got;
        if (fd < 0) {
            continue;
        }
        if (send(fd, query, query_len, 0) < 0) {
            close(fd);
            continue;
        }
        got = recv(fd, response, response_len, 0);
        close(fd);
        if (got > 0) {
            if (upstream_index != NULL) {
                *upstream_index = i;
            }
            return got;
        }
    }
    return -1;
}

static ssize_t forward_udp_probe_one(const upstream_t *upstream, int timeout_ms,
                                     const uint8_t *query, size_t query_len,
                                     uint8_t *response, size_t response_len) {
    int fd;
    ssize_t got;
    fd = connect_upstream(upstream, SOCK_DGRAM, timeout_ms);
    if (fd < 0) {
        return -1;
    }
    if (send(fd, query, query_len, 0) < 0) {
        close(fd);
        return -1;
    }
    got = recv(fd, response, response_len, 0);
    close(fd);
    return got;
}

static ssize_t read_full(int fd, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n <= 0) {
            return -1;
        }
        got += (size_t) n;
    }
    return (ssize_t) got;
}

static ssize_t forward_tcp(const config_t *cfg, const uint8_t *query, size_t query_len, uint8_t *response, size_t response_len) {
    int i;
    uint8_t lenbuf[2];
    if (query_len > 65535) {
        return -1;
    }
    lenbuf[0] = (uint8_t) ((query_len >> 8) & 0xffu);
    lenbuf[1] = (uint8_t) (query_len & 0xffu);
    for (i = 0; i < cfg->upstream_count; i++) {
        uint8_t rlenbuf[2];
        uint16_t rlen;
        int fd = connect_upstream(&cfg->upstreams[i], SOCK_STREAM, cfg->timeout_ms);
        if (fd < 0) {
            continue;
        }
        if (send(fd, lenbuf, 2, 0) != 2 || send(fd, query, query_len, 0) != (ssize_t) query_len) {
            close(fd);
            continue;
        }
        if (read_full(fd, rlenbuf, 2) != 2) {
            close(fd);
            continue;
        }
        rlen = (uint16_t) ((rlenbuf[0] << 8) | rlenbuf[1]);
        if (rlen == 0 || rlen > response_len) {
            close(fd);
            continue;
        }
        if (read_full(fd, response, rlen) != rlen) {
            close(fd);
            continue;
        }
        close(fd);
        return rlen;
    }
    return -1;
}

static void default_config(config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->listen_port = DEFAULT_PORT;
    cfg->fail_open = 1;
    cfg->timeout_ms = DEFAULT_TIMEOUT_MS;
    safe_copy(cfg->control_socket, sizeof(cfg->control_socket), "/data/local/tmp/afwall_dnsd.sock");
    cfg->upstream_count = 1;
    safe_copy(cfg->upstreams[0].host, sizeof(cfg->upstreams[0].host), "1.1.1.1");
    cfg->upstreams[0].port = 53;
}

static bool parse_upstream(config_t *cfg, const char *value) {
    const char *colon;
    upstream_t *upstream;
    if (cfg->upstream_count >= MAX_UPSTREAMS || value == NULL || value[0] == '\0') {
        return false;
    }
    upstream = &cfg->upstreams[cfg->upstream_count];
    memset(upstream, 0, sizeof(*upstream));
    colon = strrchr(value, ':');
    if (colon != NULL && colon[1] != '\0') {
        char host[128];
        size_t host_len = (size_t) (colon - value);
        if (host_len >= sizeof(host)) {
            return false;
        }
        memcpy(host, value, host_len);
        host[host_len] = '\0';
        safe_copy(upstream->host, sizeof(upstream->host), host);
        upstream->port = atoi(colon + 1);
    } else {
        safe_copy(upstream->host, sizeof(upstream->host), value);
        upstream->port = 53;
    }
    if (upstream->port <= 0 || upstream->port > 65535) {
        upstream->port = 53;
    }
    cfg->upstream_count++;
    return true;
}

static void load_string_rule_file(string_rule_t *rules, int *count, const char *path);
static void load_regex_rule_file(regex_rule_t *rules, int *count, const char *path);

static bool load_config(const char *path, config_t *new_cfg) {
    FILE *fp;
    char line[1024];
    default_config(new_cfg);
    fp = fopen(path, "r");
    if (fp == NULL) {
        return false;
    }
    new_cfg->upstream_count = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *eq;
        char *key = line;
        char *value;
        trim(line);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        eq = strchr(line, '=');
        if (eq == NULL) {
            continue;
        }
        *eq = '\0';
        value = eq + 1;
        trim(key);
        trim(value);
        if (strcmp(key, "port") == 0) {
            int port = atoi(value);
            if (port > 0 && port <= 65535) {
                new_cfg->listen_port = port;
            }
        } else if (strcmp(key, "control_socket") == 0) {
            safe_copy(new_cfg->control_socket, sizeof(new_cfg->control_socket), value);
        } else if (strcmp(key, "log_file") == 0) {
            safe_copy(new_cfg->log_file, sizeof(new_cfg->log_file), value);
        } else if (strcmp(key, "pid_file") == 0) {
            safe_copy(new_cfg->pid_file, sizeof(new_cfg->pid_file), value);
        } else if (strcmp(key, "fail_open") == 0) {
            new_cfg->fail_open = atoi(value) != 0;
        } else if (strcmp(key, "strict_mode") == 0) {
            new_cfg->strict_mode = atoi(value) != 0;
        } else if (strcmp(key, "timeout_ms") == 0) {
            int timeout = atoi(value);
            if (timeout >= 250 && timeout <= 10000) {
                new_cfg->timeout_ms = timeout;
            }
        } else if (strcmp(key, "upstream") == 0) {
            parse_upstream(new_cfg, value);
        } else if (strcmp(key, "allow_exact") == 0) {
            add_string_rule(new_cfg->exact_allow, &new_cfg->exact_allow_count, value);
        } else if (strcmp(key, "allow_exact_file") == 0) {
            load_string_rule_file(new_cfg->exact_allow, &new_cfg->exact_allow_count, value);
        } else if (strcmp(key, "allow_suffix") == 0) {
            add_string_rule(new_cfg->suffix_allow, &new_cfg->suffix_allow_count, value);
        } else if (strcmp(key, "allow_suffix_file") == 0) {
            load_string_rule_file(new_cfg->suffix_allow, &new_cfg->suffix_allow_count, value);
        } else if (strcmp(key, "block_exact") == 0) {
            add_string_rule(new_cfg->exact_block, &new_cfg->exact_block_count, value);
        } else if (strcmp(key, "block_exact_file") == 0) {
            load_string_rule_file(new_cfg->exact_block, &new_cfg->exact_block_count, value);
        } else if (strcmp(key, "block_suffix") == 0) {
            add_string_rule(new_cfg->suffix_block, &new_cfg->suffix_block_count, value);
        } else if (strcmp(key, "block_suffix_file") == 0) {
            load_string_rule_file(new_cfg->suffix_block, &new_cfg->suffix_block_count, value);
        } else if (strcmp(key, "allow_regex") == 0) {
            add_regex_rule(new_cfg->regex_allow, &new_cfg->regex_allow_count, value);
        } else if (strcmp(key, "allow_regex_file") == 0) {
            load_regex_rule_file(new_cfg->regex_allow, &new_cfg->regex_allow_count, value);
        } else if (strcmp(key, "block_regex") == 0) {
            add_regex_rule(new_cfg->regex_block, &new_cfg->regex_block_count, value);
        } else if (strcmp(key, "block_regex_file") == 0) {
            load_regex_rule_file(new_cfg->regex_block, &new_cfg->regex_block_count, value);
        } else if (strcmp(key, "temp_allow") == 0) {
            add_temp_rule(new_cfg->temp_allow, &new_cfg->temp_allow_count, value);
        } else if (strcmp(key, "temp_block") == 0) {
            add_temp_rule(new_cfg->temp_block, &new_cfg->temp_block_count, value);
        }
    }
    fclose(fp);
    if (new_cfg->upstream_count == 0) {
        safe_copy(new_cfg->upstreams[0].host, sizeof(new_cfg->upstreams[0].host), "1.1.1.1");
        new_cfg->upstreams[0].port = 53;
        new_cfg->upstream_count = 1;
    }
    new_cfg->generation = g_cfg.generation + 1;
    return true;
}

static void load_string_rule_file(string_rule_t *rules, int *count, const char *path) {
    FILE *fp;
    char line[1024];
    if (path == NULL || path[0] == '\0') {
        return;
    }
    fp = fopen(path, "r");
    if (fp == NULL) {
        return;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        trim(line);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        add_string_rule(rules, count, line);
    }
    fclose(fp);
}

static void load_regex_rule_file(regex_rule_t *rules, int *count, const char *path) {
    FILE *fp;
    char line[1024];
    if (path == NULL || path[0] == '\0') {
        return;
    }
    fp = fopen(path, "r");
    if (fp == NULL) {
        return;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        trim(line);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        add_regex_rule(rules, count, line);
    }
    fclose(fp);
}

static bool reload_config(void) {
    config_t *next = (config_t *) calloc(1, sizeof(config_t));
    if (next == NULL) {
        return false;
    }
    if (!load_config(g_config_path, next)) {
        free(next);
        return false;
    }
    free_regex_rules(&g_cfg);
    g_cfg = *next;
    free(next);
    memset(g_cache, 0, sizeof(g_cache));
    g_stats.reloads++;
    return true;
}

static void write_pid_file(void) {
    FILE *fp;
    if (g_cfg.pid_file[0] == '\0') {
        return;
    }
    fp = fopen(g_cfg.pid_file, "w");
    if (fp != NULL) {
        fprintf(fp, "%ld\n", (long) getpid());
        fclose(fp);
    }
}

static int create_udp_socket(int port) {
    int fd;
    int off = 0;
    int on = 1;
    struct sockaddr_in6 addr6;
    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_addr = in6addr_any;
    addr6.sin6_port = htons((uint16_t) port);
    if (bind(fd, (struct sockaddr *) &addr6, sizeof(addr6)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int create_tcp_socket(int port) {
    int fd;
    int off = 0;
    int on = 1;
    struct sockaddr_in6 addr6;
    fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_addr = in6addr_any;
    addr6.sin6_port = htons((uint16_t) port);
    if (bind(fd, (struct sockaddr *) &addr6, sizeof(addr6)) != 0 || listen(fd, 16) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int create_control_socket(const char *path) {
    int fd;
    struct sockaddr_un addr;
    if (path == NULL || path[0] == '\0') {
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    unlink(path);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    safe_copy(addr.sun_path, sizeof(addr.sun_path), path);
    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0 || listen(fd, 4) != 0) {
        close(fd);
        return -1;
    }
    chmod(path, 0666);
    return fd;
}

static void finish_dns_query(const char *domain, const char *action, const struct timeval *start) {
    struct timeval end;
    int latency_ms;
    gettimeofday(&end, NULL);
    latency_ms = elapsed_ms(start, &end);
    record_query_latency(latency_ms);
    add_log(domain, action, latency_ms);
}

static void handle_dns_query(const config_t *cfg, const uint8_t *query, size_t query_len,
                             uint8_t *response, size_t *response_len, const char **action_out,
                             int tcp) {
    char domain[MAX_DOMAIN];
    uint16_t qtype = 0;
    const char *reason = "parse";
    ssize_t forwarded;
    struct timeval start;
    struct timeval upstream_start;
    struct timeval upstream_end;
    int upstream_latency_ms;
    gettimeofday(&start, NULL);
    g_stats.queries++;
    if (tcp) {
        g_stats.tcp_queries++;
    } else {
        g_stats.udp_queries++;
    }
    if (!parse_qname(query, query_len, domain, sizeof(domain), &qtype)) {
        *response_len = build_block_response(query, query_len, response, MAX_PACKET);
        *action_out = "invalid";
        g_stats.invalid_queries++;
        g_stats.blocked++;
        finish_dns_query("unknown", "invalid", &start);
        return;
    }
    if (evaluate_domain(cfg, domain, &reason) == DECISION_BLOCK) {
        *response_len = build_block_response(query, query_len, response, MAX_PACKET);
        g_stats.blocked++;
        *action_out = reason;
        finish_dns_query(domain, reason, &start);
        return;
    }
    if (cache_lookup(domain, qtype, query, response, response_len)) {
        g_stats.cache_hits++;
        g_stats.allowed++;
        *action_out = "cache";
        finish_dns_query(domain, "cache", &start);
        return;
    }
    g_stats.cache_misses++;
    g_stats.upstream_requests++;
    gettimeofday(&upstream_start, NULL);
    forwarded = tcp
            ? forward_tcp(cfg, query, query_len, response, MAX_PACKET)
            : forward_udp(cfg, query, query_len, response, MAX_PACKET);
    gettimeofday(&upstream_end, NULL);
    upstream_latency_ms = elapsed_ms(&upstream_start, &upstream_end);
    if (upstream_latency_ms > 0) {
        g_stats.upstream_latency_ms += (uint64_t) upstream_latency_ms;
    }
    if (forwarded > 0) {
        *response_len = (size_t) forwarded;
        cache_store(domain, qtype, response, *response_len);
        g_stats.allowed++;
        g_stats.upstream_successes++;
        *action_out = "upstream";
        finish_dns_query(domain, "upstream", &start);
        return;
    }
    g_stats.upstream_failures++;
    if (cfg->fail_open) {
        *response_len = 0;
        *action_out = "upstream_failed";
        g_stats.fail_open_drops++;
    } else {
        *response_len = build_block_response(query, query_len, response, MAX_PACKET);
        g_stats.blocked++;
        *action_out = "fail_closed";
        g_stats.fail_closed_blocks++;
    }
    finish_dns_query(domain, *action_out, &start);
}

static void handle_udp(int fd) {
    uint8_t query[MAX_PACKET];
    uint8_t response[MAX_PACKET];
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);
    ssize_t got;
    size_t response_len = 0;
    const char *action = "none";
    struct timeval start;
    struct timeval end;
    got = recvfrom(fd, query, sizeof(query), 0, (struct sockaddr *) &peer, &peer_len);
    if (got <= 0) {
        return;
    }
    gettimeofday(&start, NULL);
    handle_dns_query(&g_cfg, query, (size_t) got, response, &response_len, &action, 0);
    gettimeofday(&end, NULL);
    (void) action;
    if (response_len > 0) {
        sendto(fd, response, response_len, 0, (struct sockaddr *) &peer, peer_len);
    }
    if (response_len == 0 && !g_cfg.fail_open) {
        add_log("unknown", "no_response", elapsed_ms(&start, &end));
    }
}

static void handle_tcp_client(int client) {
    uint8_t lenbuf[2];
    uint8_t query[MAX_PACKET];
    uint8_t response[MAX_PACKET + 2];
    uint16_t qlen;
    size_t response_len = 0;
    const char *action = "none";
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (read_full(client, lenbuf, 2) != 2) {
        return;
    }
    qlen = (uint16_t) ((lenbuf[0] << 8) | lenbuf[1]);
    if (qlen == 0 || qlen > MAX_PACKET) {
        return;
    }
    if (read_full(client, query, qlen) != qlen) {
        return;
    }
    handle_dns_query(&g_cfg, query, qlen, response + 2, &response_len, &action, 1);
    (void) action;
    if (response_len > 0) {
        response[0] = (uint8_t) ((response_len >> 8) & 0xffu);
        response[1] = (uint8_t) (response_len & 0xffu);
        send(client, response, response_len + 2, 0);
    }
}

static void handle_tcp(int fd) {
    int client = accept(fd, NULL, NULL);
    if (client >= 0) {
        handle_tcp_client(client);
        close(client);
    }
}

static void write_control_response(int fd, const char *fmt, ...) {
    char buf[4096];
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        send(fd, buf, (size_t) n, 0);
    }
}

static size_t build_health_query(uint8_t *out, size_t out_len) {
    uint16_t id = (uint16_t) ((now_seconds() ^ (uint64_t) getpid()) & 0xffffu);
    const uint8_t qname[] = {
            7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
            3, 'c', 'o', 'm',
            0
    };
    size_t pos = 12;
    if (out_len < pos + sizeof(qname) + 4) {
        return 0;
    }
    memset(out, 0, out_len);
    out[0] = (uint8_t) ((id >> 8) & 0xffu);
    out[1] = (uint8_t) (id & 0xffu);
    out[2] = 0x01;
    out[5] = 0x01;
    memcpy(out + pos, qname, sizeof(qname));
    pos += sizeof(qname);
    out[pos++] = 0x00;
    out[pos++] = 0x01;
    out[pos++] = 0x00;
    out[pos++] = 0x01;
    return pos;
}

static int response_rcode(const uint8_t *response, size_t response_len) {
    if (response_len < 4) {
        return -1;
    }
    return response[3] & 0x0f;
}

static void write_health_response(int client) {
    uint8_t query[MAX_PACKET];
    uint8_t response[MAX_PACKET];
    struct timeval start;
    struct timeval end;
    size_t query_len;
    ssize_t response_len;
    int latency_ms;
    int upstream_index = -1;
    int rcode;

    query_len = build_health_query(query, sizeof(query));
    gettimeofday(&start, NULL);
    response_len = query_len == 0
            ? -1
            : forward_udp_probe(&g_cfg, query, query_len, response, sizeof(response), &upstream_index);
    gettimeofday(&end, NULL);
    latency_ms = elapsed_ms(&start, &end);
    rcode = response_len > 0 ? response_rcode(response, (size_t) response_len) : -1;

    write_control_response(client,
            "health=1\nrunning=1\npid=%ld\nuptime=%llu\nlisten_port=%d\n"
            "generation=%llu\nupstreams=%d\nupstream_probe=%s\n"
            "upstream_probe_ms=%d\nupstream_probe_index=%d\nupstream_probe_rcode=%d\n"
            "queries=%llu\nblocked=%llu\nallowed=%llu\ncache_entries=%d\n"
            "rules_total=%d\n",
            (long) getpid(),
            (unsigned long long) (now_seconds() - g_stats.start_time),
            g_cfg.listen_port,
            (unsigned long long) g_cfg.generation,
            g_cfg.upstream_count,
            response_len > 0 ? "ok" : "fail",
            latency_ms,
            upstream_index,
            rcode,
            (unsigned long long) g_stats.queries,
            (unsigned long long) g_stats.blocked,
            (unsigned long long) g_stats.allowed,
            cache_entry_count(),
            g_cfg.exact_allow_count + g_cfg.suffix_allow_count
                    + g_cfg.exact_block_count + g_cfg.suffix_block_count
                    + g_cfg.regex_allow_count + g_cfg.regex_block_count
                    + g_cfg.temp_allow_count + g_cfg.temp_block_count);
}

static void write_benchmark_response(int client) {
    uint8_t query[MAX_PACKET];
    size_t query_len;
    int timeout_ms;
    int i;

    query_len = build_health_query(query, sizeof(query));
    timeout_ms = g_cfg.timeout_ms < 1000 ? g_cfg.timeout_ms : 1000;
    if (timeout_ms < 250) {
        timeout_ms = 250;
    }

    write_control_response(client, "benchmark=1\nupstreams=%d\ntimeout_ms=%d\n",
            g_cfg.upstream_count, timeout_ms);
    if (query_len == 0) {
        write_control_response(client, "error=unable_to_build_query\n");
        return;
    }

    for (i = 0; i < g_cfg.upstream_count; i++) {
        uint8_t response[MAX_PACKET];
        struct timeval start;
        struct timeval end;
        ssize_t response_len;
        int latency_ms;
        int rcode;

        gettimeofday(&start, NULL);
        response_len = forward_udp_probe_one(&g_cfg.upstreams[i], timeout_ms, query, query_len,
                response, sizeof(response));
        gettimeofday(&end, NULL);
        latency_ms = elapsed_ms(&start, &end);
        rcode = response_len > 0 ? response_rcode(response, (size_t) response_len) : -1;

        write_control_response(client,
                "upstream[%d]=%s:%d status=%s latency_ms=%d rcode=%d bytes=%ld\n",
                i,
                g_cfg.upstreams[i].host,
                g_cfg.upstreams[i].port,
                response_len > 0 ? "ok" : "fail",
                latency_ms,
                rcode,
                (long) response_len);
    }
}

static void handle_control(int fd) {
    int client = accept(fd, NULL, NULL);
    char cmd[128];
    ssize_t n;
    if (client < 0) {
        return;
    }
    n = recv(client, cmd, sizeof(cmd) - 1, 0);
    if (n <= 0) {
        close(client);
        return;
    }
    cmd[n] = '\0';
    trim(cmd);
    if (strcmp(cmd, "status") == 0 || strcmp(cmd, "stats") == 0) {
        write_control_response(client,
                "running=1\npid=%ld\nuptime=%llu\ngeneration=%llu\n"
                "queries=%llu\nudp_queries=%llu\ntcp_queries=%llu\ninvalid_queries=%llu\n"
                "allowed=%llu\nblocked=%llu\nfail_open_drops=%llu\nfail_closed_blocks=%llu\n"
                "cache_size=%d\ncache_entries=%d\ncache_hits=%llu\ncache_misses=%llu\n"
                "cache_hit_rate_ppm=%llu\ncache_stores=%llu\ncache_expired=%llu\ncache_evictions=%llu\n"
                "upstream_requests=%llu\nupstream_successes=%llu\nupstream_failures=%llu\n"
                "avg_latency_ms=%llu\nmax_latency_ms=%llu\nupstream_avg_latency_ms=%llu\n"
                "reloads=%llu\nrules_exact_allow=%d\nrules_suffix_allow=%d\nrules_exact_block=%d\n"
                "rules_suffix_block=%d\nrules_regex_allow=%d\nrules_regex_block=%d\n"
                "rules_temp_allow=%d\nrules_temp_block=%d\n",
                (long) getpid(),
                (unsigned long long) (now_seconds() - g_stats.start_time),
                (unsigned long long) g_cfg.generation,
                (unsigned long long) g_stats.queries,
                (unsigned long long) g_stats.udp_queries,
                (unsigned long long) g_stats.tcp_queries,
                (unsigned long long) g_stats.invalid_queries,
                (unsigned long long) g_stats.allowed,
                (unsigned long long) g_stats.blocked,
                (unsigned long long) g_stats.fail_open_drops,
                (unsigned long long) g_stats.fail_closed_blocks,
                CACHE_SIZE,
                cache_entry_count(),
                (unsigned long long) g_stats.cache_hits,
                (unsigned long long) g_stats.cache_misses,
                (unsigned long long) div_u64(g_stats.cache_hits * 1000000ULL,
                        g_stats.cache_hits + g_stats.cache_misses),
                (unsigned long long) g_stats.cache_stores,
                (unsigned long long) g_stats.cache_expired,
                (unsigned long long) g_stats.cache_evictions,
                (unsigned long long) g_stats.upstream_requests,
                (unsigned long long) g_stats.upstream_successes,
                (unsigned long long) g_stats.upstream_failures,
                (unsigned long long) div_u64(g_stats.total_latency_ms, g_stats.queries),
                (unsigned long long) g_stats.max_latency_ms,
                (unsigned long long) div_u64(g_stats.upstream_latency_ms, g_stats.upstream_requests),
                (unsigned long long) g_stats.reloads,
                g_cfg.exact_allow_count,
                g_cfg.suffix_allow_count,
                g_cfg.exact_block_count,
                g_cfg.suffix_block_count,
                g_cfg.regex_allow_count,
                g_cfg.regex_block_count,
                g_cfg.temp_allow_count,
                g_cfg.temp_block_count);
    } else if (strcmp(cmd, "health") == 0) {
        write_health_response(client);
    } else if (strcmp(cmd, "benchmark") == 0) {
        write_benchmark_response(client);
    } else if (strcmp(cmd, "reload") == 0) {
        if (reload_config()) {
            write_control_response(client, "ok reload generation=%llu\n", (unsigned long long) g_cfg.generation);
        } else {
            write_control_response(client, "error reload\n");
        }
    } else if (strcmp(cmd, "logs") == 0) {
        int i;
        for (i = 0; i < LOG_RING; i++) {
            int idx = (g_log_pos + i) % LOG_RING;
            if (g_logs[idx].timestamp == 0) {
                continue;
            }
            write_control_response(client, "%llu %s %s %dms\n",
                    (unsigned long long) g_logs[idx].timestamp,
                    g_logs[idx].action,
                    g_logs[idx].domain,
                    g_logs[idx].latency_ms);
        }
    } else if (strcmp(cmd, "stop") == 0) {
        write_control_response(client, "ok stopping\n");
        g_running = 0;
    } else {
        write_control_response(client, "error unknown_command\n");
    }
    close(client);
}

static void signal_handler(int signo) {
    if (signo == SIGTERM || signo == SIGINT) {
        g_running = 0;
    } else if (signo == SIGHUP) {
        reload_config();
    }
}

static void usage(const char *argv0) {
    fprintf(stderr, "usage: %s --config <path>\n", argv0);
}

int main(int argc, char **argv) {
    int udp_fd;
    int tcp_fd;
    int control_fd;
    int i;
    default_config(&g_cfg);
    g_stats.start_time = now_seconds();
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            safe_copy(g_config_path, sizeof(g_config_path), argv[++i]);
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (g_config_path[0] == '\0') {
        usage(argv[0]);
        return 2;
    }
    if (!reload_config()) {
        fprintf(stderr, "failed to load config: %s\n", g_config_path);
        return 1;
    }
    write_pid_file();
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);
    udp_fd = create_udp_socket(g_cfg.listen_port);
    tcp_fd = create_tcp_socket(g_cfg.listen_port);
    control_fd = create_control_socket(g_cfg.control_socket);
    if (udp_fd < 0 || tcp_fd < 0 || control_fd < 0) {
        fprintf(stderr, "failed to create listeners on port %d\n", g_cfg.listen_port);
        return 1;
    }
    while (g_running) {
        fd_set readfds;
        struct timeval timeout;
        int maxfd = udp_fd;
        int ready;
        FD_ZERO(&readfds);
        FD_SET(udp_fd, &readfds);
        FD_SET(tcp_fd, &readfds);
        FD_SET(control_fd, &readfds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        if (tcp_fd > maxfd) {
            maxfd = tcp_fd;
        }
        if (control_fd > maxfd) {
            maxfd = control_fd;
        }
        ready = select(maxfd + 1, &readfds, NULL, NULL, &timeout);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (FD_ISSET(udp_fd, &readfds)) {
            handle_udp(udp_fd);
        }
        if (FD_ISSET(tcp_fd, &readfds)) {
            handle_tcp(tcp_fd);
        }
        if (FD_ISSET(control_fd, &readfds)) {
            handle_control(control_fd);
        }
        flush_logs();
    }
    flush_logs();
    close(udp_fd);
    close(tcp_fd);
    close(control_fd);
    unlink(g_cfg.control_socket);
    unlink(g_cfg.pid_file);
    free_regex_rules(&g_cfg);
    return 0;
}
