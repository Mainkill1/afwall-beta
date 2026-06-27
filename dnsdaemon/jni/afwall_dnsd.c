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
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
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
#define MAX_LABEL 64
#define INITIAL_RULE_CAPACITY 1024
#define INITIAL_REGEX_CAPACITY 16
#define MIN_EXACT_INDEX_SIZE 65536
#define MAX_EXACT_INDEX_SIZE (1 << 24)
#define MAX_TEMP_RULES 1024
#define MAX_UPSTREAMS 8
#define MAX_SPLIT_UPSTREAMS 32
#define DEFAULT_CACHE_SIZE 1024
#define MAX_CACHE_SIZE 4096
#define LOG_RING 256
#define LOG_HISTORY_LIMIT 512
#define LOG_LINE_MAX 512
#define DEFAULT_PORT 5354
#define DEFAULT_TIMEOUT_MS 2500
#define CLIENT_TIMEOUT_MS 5000
#define DEFAULT_POSITIVE_TTL 60
#define DEFAULT_NEGATIVE_TTL 30
#define MAX_CACHE_TTL 86400
#define DNS_SOCKET_BUFFER_BYTES 262144
#define UDP_DRAIN_LIMIT 32
#define UID_UNKNOWN -1
#define UID_CACHE_SIZE 128
#define UID_CACHE_TTL 15
#define DNS_QTYPE_A 1
#define DNS_QTYPE_AAAA 28
#define DNS_CLASS_IN 1
#define SAFE_SEARCH_TTL 300

#ifndef MSG_DONTWAIT
#define AFWALL_HAS_MSG_DONTWAIT 0
#define MSG_DONTWAIT 0
#else
#define AFWALL_HAS_MSG_DONTWAIT 1
#endif

typedef enum {
    DECISION_ALLOW = 0,
    DECISION_BLOCK = 1
} decision_t;

typedef struct {
    char value[MAX_DOMAIN];
} string_rule_t;

typedef struct {
    string_rule_t *items;
    int count;
    int capacity;
} string_rule_list_t;

typedef struct {
    int uid;
    char domain[MAX_DOMAIN];
} app_exact_rule_t;

typedef struct {
    app_exact_rule_t *items;
    int count;
    int capacity;
} app_exact_rule_list_t;

typedef struct {
    regex_t compiled;
    char pattern[MAX_DOMAIN];
    bool valid;
} regex_rule_t;

typedef struct {
    regex_rule_t *items;
    int count;
    int capacity;
} regex_rule_list_t;

typedef struct {
    char value[MAX_DOMAIN];
    uint64_t expires_at;
} temp_rule_t;

typedef enum {
    UPSTREAM_PROTO_AUTO = 0,
    UPSTREAM_PROTO_UDP = 1,
    UPSTREAM_PROTO_TCP = 2
} upstream_protocol_t;

typedef struct {
    char host[128];
    int port;
    upstream_protocol_t protocol;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int udp_fd;
} upstream_t;

typedef struct {
    char suffix[MAX_DOMAIN];
    upstream_t upstream;
} split_upstream_t;

typedef struct {
    char ipv4[INET_ADDRSTRLEN];
    char ipv6[INET6_ADDRSTRLEN];
} safe_search_target_t;

typedef struct {
    char label[MAX_LABEL];
    int first_child;
    int next_sibling;
    bool terminal;
} suffix_trie_node_t;

typedef struct {
    suffix_trie_node_t *nodes;
    int count;
    int capacity;
} suffix_trie_t;

typedef struct {
    char label[MAX_LABEL];
    int first_child;
    int next_sibling;
    int *uids;
    int uid_count;
    int uid_capacity;
} app_suffix_trie_node_t;

typedef struct {
    app_suffix_trie_node_t *nodes;
    int count;
    int capacity;
} app_suffix_trie_t;

typedef struct {
    int listen_port;
    int strict_mode;
    int fail_open;
    int timeout_ms;
    int cache_size;
    int query_logging;
    int persist_query_logs;
    int safe_search;
    char control_socket[256];
    char log_file[256];
    char pid_file[256];
    char heartbeat_file[256];
    safe_search_target_t safe_google;
    safe_search_target_t safe_youtube;
    safe_search_target_t safe_bing;
    safe_search_target_t safe_duckduckgo;
    upstream_t upstreams[MAX_UPSTREAMS];
    int upstream_count;
    split_upstream_t split_upstreams[MAX_SPLIT_UPSTREAMS];
    int split_upstream_count;
    string_rule_list_t exact_allow;
    string_rule_list_t suffix_allow;
    string_rule_list_t exact_block;
    string_rule_list_t suffix_block;
    app_exact_rule_list_t app_exact_allow;
    app_exact_rule_list_t app_exact_block;
    app_exact_rule_list_t app_suffix_allow;
    app_exact_rule_list_t app_suffix_block;
    int *app_exact_allow_index;
    int app_exact_allow_index_size;
    int *app_exact_block_index;
    int app_exact_block_index_size;
    int *exact_allow_index;
    int exact_allow_index_size;
    int *exact_block_index;
    int exact_block_index_size;
    suffix_trie_t suffix_allow_trie;
    suffix_trie_t suffix_block_trie;
    app_suffix_trie_t app_suffix_allow_trie;
    app_suffix_trie_t app_suffix_block_trie;
    regex_rule_list_t regex_allow;
    regex_rule_list_t regex_block;
    temp_rule_t temp_allow[MAX_TEMP_RULES];
    temp_rule_t temp_block[MAX_TEMP_RULES];
    int temp_allow_count;
    int temp_block_count;
    uint64_t resolver_scope_hash;
    uint64_t generation;
} config_t;

typedef struct {
    uint64_t queries;
    uint64_t allowed;
    uint64_t blocked;
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t cache_stores;
    uint64_t cache_positive_hits;
    uint64_t cache_negative_hits;
    uint64_t cache_positive_stores;
    uint64_t cache_negative_stores;
    uint64_t cache_expired;
    uint64_t cache_evictions;
    uint64_t cache_ttl_rewrites;
    uint64_t cache_lru_evictions;
    uint64_t cache_reload_preserved;
    uint64_t cache_reload_dropped;
    uint64_t cache_reload_scope_changes;
    uint64_t udp_queries;
    uint64_t tcp_queries;
    uint64_t invalid_queries;
    uint64_t udp_drain_batches;
    uint64_t udp_drain_packets;
    uint64_t tcp_client_timeouts;
    uint64_t control_client_timeouts;
    uint64_t fail_open_drops;
    uint64_t fail_closed_blocks;
    uint64_t safe_search_rewrites;
    uint64_t upstream_requests;
    uint64_t upstream_successes;
    uint64_t upstream_failures;
    uint64_t upstream_tcp_fallbacks;
    uint64_t upstream_truncated_responses;
    uint64_t upstream_udp_socket_reuses;
    uint64_t upstream_udp_stale_replies;
    uint64_t total_latency_ms;
    uint64_t upstream_latency_ms;
    uint64_t max_latency_ms;
    uint64_t reloads;
    uint64_t uid_lookup_successes;
    uint64_t uid_lookup_misses;
    uint64_t uid_cache_hits;
    uint64_t start_time;
} stats_t;

typedef struct {
    uint64_t seq;
    char domain[MAX_DOMAIN];
    char action[32];
    char transport[8];
    char source[64];
    int uid;
    char result[16];
    char rule[32];
    char upstream[32];
    uint16_t qtype;
    int latency_ms;
    uint64_t timestamp;
} log_entry_t;

typedef struct {
    char domain[MAX_DOMAIN];
    uint16_t qtype;
    uint8_t response[MAX_PACKET];
    size_t response_len;
    time_t cached_at;
    time_t last_access;
    time_t expires_at;
    uint32_t hash;
    bool used;
    bool negative;
} cache_entry_t;

typedef struct {
    uint16_t port;
    int family;
    int tcp;
    int uid;
    uint64_t expires_at;
    bool used;
} uid_cache_entry_t;

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_reload_requested = 0;
static config_t g_cfg;
static stats_t g_stats;
static log_entry_t g_logs[LOG_RING];
static int g_log_pos = 0;
static uint64_t g_log_seq = 0;
static uint64_t g_log_flushed_seq = 0;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_log_flush_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_log_thread;
static bool g_log_thread_started = false;
static volatile sig_atomic_t g_log_thread_running = 0;
static char g_log_file_path[256];
static bool g_log_persistence_enabled = true;
static cache_entry_t *g_cache = NULL;
static int g_cache_capacity = 0;
static uid_cache_entry_t g_uid_cache[UID_CACHE_SIZE];
static int g_uid_cache_pos = 0;
static char g_config_path[256];

static void write_control_response(int fd, const char *fmt, ...);

static bool config_bool_value(const char *value) {
    return value != NULL && atoi(value) != 0;
}

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

static long read_proc_status_kb(const char *key) {
    FILE *fp;
    char line[256];
    char prefix[64];
    size_t prefix_len;
    long value = 0;
    if (key == NULL || key[0] == '\0') {
        return 0;
    }
    snprintf(prefix, sizeof(prefix), "%s:", key);
    prefix_len = strlen(prefix);
    fp = fopen("/proc/self/status", "r");
    if (fp == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strncmp(line, prefix, prefix_len) == 0) {
            char *p = line + prefix_len;
            while (*p && !isdigit((unsigned char) *p)) {
                p++;
            }
            value = strtol(p, NULL, 10);
            break;
        }
    }
    fclose(fp);
    return value < 0 ? 0 : value;
}

static bool read_proc_cpu_ticks(uint64_t *user_ticks, uint64_t *system_ticks) {
    FILE *fp;
    char line[1024];
    char *end_comm;
    char *token;
    int field = 3;
    uint64_t user = 0;
    uint64_t system = 0;
    if (user_ticks != NULL) {
        *user_ticks = 0;
    }
    if (system_ticks != NULL) {
        *system_ticks = 0;
    }
    fp = fopen("/proc/self/stat", "r");
    if (fp == NULL) {
        return false;
    }
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return false;
    }
    fclose(fp);
    end_comm = strrchr(line, ')');
    if (end_comm == NULL || end_comm[1] == '\0') {
        return false;
    }
    token = strtok(end_comm + 2, " ");
    while (token != NULL) {
        if (field == 14) {
            user = strtoull(token, NULL, 10);
        } else if (field == 15) {
            system = strtoull(token, NULL, 10);
            break;
        }
        field++;
        token = strtok(NULL, " ");
    }
    if (user_ticks != NULL) {
        *user_ticks = user;
    }
    if (system_ticks != NULL) {
        *system_ticks = system;
    }
    return field >= 15;
}

static bool ascii_contains_ci(const char *haystack, const char *needle) {
    size_t needle_len;
    const char *p;
    if (needle == NULL || needle[0] == '\0') {
        return true;
    }
    if (haystack == NULL) {
        return false;
    }
    needle_len = strlen(needle);
    if (needle_len == 0) {
        return true;
    }
    for (p = haystack; *p != '\0'; p++) {
        size_t i;
        for (i = 0; i < needle_len; i++) {
            unsigned char hc = (unsigned char) p[i];
            unsigned char nc = (unsigned char) needle[i];
            if (hc == '\0') {
                return false;
            }
            if (tolower(hc) != tolower(nc)) {
                break;
            }
        }
        if (i == needle_len) {
            return true;
        }
    }
    return false;
}

static uint64_t cpu_ticks_to_ms(uint64_t ticks) {
    long hz = sysconf(_SC_CLK_TCK);
    if (hz <= 0) {
        return 0;
    }
    return div_u64(ticks * 1000ULL, (uint64_t) hz);
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
    if (g_cache == NULL || g_cache_capacity <= 0) {
        return 0;
    }
    for (i = 0; i < g_cache_capacity; i++) {
        if (g_cache[i].used && g_cache[i].expires_at > now) {
            count++;
        }
    }
    return count;
}

static int cache_entry_count_by_type(bool negative) {
    int count = 0;
    int i;
    time_t now = time(NULL);
    if (g_cache == NULL || g_cache_capacity <= 0) {
        return 0;
    }
    for (i = 0; i < g_cache_capacity; i++) {
        if (g_cache[i].used && g_cache[i].expires_at > now && g_cache[i].negative == negative) {
            count++;
        }
    }
    return count;
}

static void add_log(const char *domain, const char *action, const char *transport,
                    const char *source, int uid,
                    uint16_t qtype, const char *result, const char *rule,
                    const char *upstream, int latency_ms) {
    log_entry_t *entry;
    if (!g_cfg.query_logging) {
        return;
    }
    pthread_mutex_lock(&g_log_mutex);
    entry = &g_logs[g_log_pos % LOG_RING];
    entry->seq = ++g_log_seq;
    safe_copy(entry->domain, sizeof(entry->domain), domain);
    safe_copy(entry->action, sizeof(entry->action), action);
    safe_copy(entry->transport, sizeof(entry->transport), transport);
    safe_copy(entry->source, sizeof(entry->source), source == NULL ? "unknown" : source);
    entry->uid = uid;
    safe_copy(entry->result, sizeof(entry->result), result);
    safe_copy(entry->rule, sizeof(entry->rule), rule);
    safe_copy(entry->upstream, sizeof(entry->upstream), upstream);
    entry->qtype = qtype;
    entry->latency_ms = latency_ms;
    entry->timestamp = now_seconds();
    g_log_pos = (g_log_pos + 1) % LOG_RING;
    pthread_mutex_unlock(&g_log_mutex);
}

static void set_log_output(const char *path, bool persist) {
    pthread_mutex_lock(&g_log_mutex);
    safe_copy(g_log_file_path, sizeof(g_log_file_path), path == NULL ? "" : path);
    g_log_persistence_enabled = persist;
    if (!g_log_persistence_enabled) {
        g_log_flushed_seq = g_log_seq;
    }
    pthread_mutex_unlock(&g_log_mutex);
}

static bool copy_log_file_path(char *out, size_t out_len) {
    bool has_path;
    if (out == NULL || out_len == 0) {
        return false;
    }
    pthread_mutex_lock(&g_log_mutex);
    safe_copy(out, out_len, g_log_file_path);
    has_path = g_log_persistence_enabled && out[0] != '\0';
    pthread_mutex_unlock(&g_log_mutex);
    return has_path;
}

static void flush_logs(void) {
    FILE *fp;
    uint64_t first_seq;
    uint64_t seq;
    int i;
    int pending_count = 0;
    uint64_t flush_to_seq;
    log_entry_t pending[LOG_RING];
    char log_file[sizeof(g_log_file_path)];

    pthread_mutex_lock(&g_log_flush_mutex);
    pthread_mutex_lock(&g_log_mutex);
    if (!g_log_persistence_enabled || g_log_file_path[0] == '\0') {
        g_log_flushed_seq = g_log_seq;
        pthread_mutex_unlock(&g_log_mutex);
        pthread_mutex_unlock(&g_log_flush_mutex);
        return;
    }
    if (g_log_flushed_seq == g_log_seq) {
        pthread_mutex_unlock(&g_log_mutex);
        pthread_mutex_unlock(&g_log_flush_mutex);
        return;
    }

    safe_copy(log_file, sizeof(log_file), g_log_file_path);
    flush_to_seq = g_log_seq;
    first_seq = g_log_flushed_seq + 1;
    if (flush_to_seq >= LOG_RING && first_seq < flush_to_seq - LOG_RING + 1) {
        first_seq = flush_to_seq - LOG_RING + 1;
    }

    for (seq = first_seq; seq <= flush_to_seq && pending_count < LOG_RING; seq++) {
        for (i = 0; i < LOG_RING; i++) {
            const log_entry_t *entry = &g_logs[i];
            if (entry->seq == seq) {
                pending[pending_count++] = *entry;
                break;
            }
        }
    }
    pthread_mutex_unlock(&g_log_mutex);

    fp = fopen(log_file, "a");
    if (fp == NULL) {
        pthread_mutex_unlock(&g_log_flush_mutex);
        return;
    }

    for (i = 0; i < pending_count; i++) {
        const log_entry_t *entry = &pending[i];
        fprintf(fp, "%llu %s %s %dms transport=%s source=%s uid=%d qtype=%u result=%s rule=%s upstream=%s\n",
                (unsigned long long) entry->timestamp,
                entry->action,
                entry->domain,
                entry->latency_ms,
                entry->transport,
                entry->source,
                entry->uid,
                (unsigned int) entry->qtype,
                entry->result,
                entry->rule,
                entry->upstream);
    }
    fclose(fp);

    pthread_mutex_lock(&g_log_mutex);
    if (g_log_flushed_seq < flush_to_seq) {
        g_log_flushed_seq = flush_to_seq;
    }
    pthread_mutex_unlock(&g_log_mutex);
    pthread_mutex_unlock(&g_log_flush_mutex);
}

static void *log_flush_worker(void *arg) {
    (void) arg;
    while (g_log_thread_running) {
        sleep(1);
        flush_logs();
    }
    flush_logs();
    return NULL;
}

static void start_log_thread(void) {
    if (g_log_thread_started) {
        return;
    }
    g_log_thread_running = 1;
    if (pthread_create(&g_log_thread, NULL, log_flush_worker, NULL) == 0) {
        g_log_thread_started = true;
    } else {
        g_log_thread_running = 0;
    }
}

static void stop_log_thread(void) {
    if (!g_log_thread_started) {
        flush_logs();
        return;
    }
    g_log_thread_running = 0;
    pthread_join(g_log_thread, NULL);
    g_log_thread_started = false;
}

static void read_log_stats(uint64_t *ring_entries, uint64_t *unflushed_entries) {
    int i;
    uint64_t count = 0;
    uint64_t unflushed = 0;
    pthread_mutex_lock(&g_log_mutex);
    for (i = 0; i < LOG_RING; i++) {
        if (g_logs[i].timestamp != 0) {
            count++;
        }
    }
    if (g_log_seq > g_log_flushed_seq) {
        unflushed = g_log_seq - g_log_flushed_seq;
        if (unflushed > LOG_RING) {
            unflushed = LOG_RING;
        }
    }
    pthread_mutex_unlock(&g_log_mutex);
    if (ring_entries != NULL) {
        *ring_entries = count;
    }
    if (unflushed_entries != NULL) {
        *unflushed_entries = unflushed;
    }
}

static void clear_log_ring(void) {
    pthread_mutex_lock(&g_log_mutex);
    memset(g_logs, 0, sizeof(g_logs));
    g_log_pos = 0;
    g_log_flushed_seq = g_log_seq;
    pthread_mutex_unlock(&g_log_mutex);
}

static void free_regex_rule_list(regex_rule_list_t *list) {
    int i;
    if (list == NULL) {
        return;
    }
    for (i = 0; i < list->count; i++) {
        if (list->items[i].valid) {
            regfree(&list->items[i].compiled);
            list->items[i].valid = false;
        }
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static void free_suffix_trie(suffix_trie_t *trie) {
    if (trie == NULL) {
        return;
    }
    free(trie->nodes);
    trie->nodes = NULL;
    trie->count = 0;
    trie->capacity = 0;
}

static void free_app_suffix_trie(app_suffix_trie_t *trie) {
    int i;
    if (trie == NULL) {
        return;
    }
    for (i = 0; i < trie->count; i++) {
        free(trie->nodes[i].uids);
        trie->nodes[i].uids = NULL;
        trie->nodes[i].uid_count = 0;
        trie->nodes[i].uid_capacity = 0;
    }
    free(trie->nodes);
    trie->nodes = NULL;
    trie->count = 0;
    trie->capacity = 0;
}

static void free_string_rule_list(string_rule_list_t *list) {
    if (list == NULL) {
        return;
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static void free_app_exact_rule_list(app_exact_rule_list_t *list) {
    if (list == NULL) {
        return;
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static void close_upstream_udp_sockets(config_t *cfg) {
    int i;
    if (cfg == NULL) {
        return;
    }
    for (i = 0; i < cfg->upstream_count; i++) {
        if (cfg->upstreams[i].udp_fd >= 0) {
            close(cfg->upstreams[i].udp_fd);
            cfg->upstreams[i].udp_fd = -1;
        }
    }
    for (i = 0; i < cfg->split_upstream_count; i++) {
        if (cfg->split_upstreams[i].upstream.udp_fd >= 0) {
            close(cfg->split_upstreams[i].upstream.udp_fd);
            cfg->split_upstreams[i].upstream.udp_fd = -1;
        }
    }
}

static void free_config_dynamic(config_t *cfg) {
    if (cfg == NULL) {
        return;
    }
    close_upstream_udp_sockets(cfg);
    free_regex_rule_list(&cfg->regex_allow);
    free_regex_rule_list(&cfg->regex_block);
    free_string_rule_list(&cfg->exact_allow);
    free_string_rule_list(&cfg->suffix_allow);
    free_string_rule_list(&cfg->exact_block);
    free_string_rule_list(&cfg->suffix_block);
    free_app_exact_rule_list(&cfg->app_exact_allow);
    free_app_exact_rule_list(&cfg->app_exact_block);
    free_app_exact_rule_list(&cfg->app_suffix_allow);
    free_app_exact_rule_list(&cfg->app_suffix_block);
    free(cfg->app_exact_allow_index);
    cfg->app_exact_allow_index = NULL;
    cfg->app_exact_allow_index_size = 0;
    free(cfg->app_exact_block_index);
    cfg->app_exact_block_index = NULL;
    cfg->app_exact_block_index_size = 0;
    free(cfg->exact_allow_index);
    cfg->exact_allow_index = NULL;
    cfg->exact_allow_index_size = 0;
    free(cfg->exact_block_index);
    cfg->exact_block_index = NULL;
    cfg->exact_block_index_size = 0;
    free_suffix_trie(&cfg->suffix_allow_trie);
    free_suffix_trie(&cfg->suffix_block_trie);
    free_app_suffix_trie(&cfg->app_suffix_allow_trie);
    free_app_suffix_trie(&cfg->app_suffix_block_trie);
}

static bool reserve_string_rule_list(string_rule_list_t *list, int needed) {
    int next_capacity;
    string_rule_t *items;
    if (list == NULL || needed < 0) {
        return false;
    }
    if (list->capacity >= needed) {
        return true;
    }
    next_capacity = list->capacity <= 0 ? INITIAL_RULE_CAPACITY : list->capacity;
    while (next_capacity < needed) {
        if (next_capacity > INT_MAX / 2) {
            return false;
        }
        next_capacity *= 2;
    }
    items = (string_rule_t *) realloc(list->items,
            (size_t) next_capacity * sizeof(string_rule_t));
    if (items == NULL) {
        return false;
    }
    memset(items + list->capacity, 0,
            (size_t) (next_capacity - list->capacity) * sizeof(string_rule_t));
    list->items = items;
    list->capacity = next_capacity;
    return true;
}

static bool add_string_rule(string_rule_list_t *rules, const char *value) {
    if (rules == NULL || value == NULL || value[0] == '\0') {
        return false;
    }
    if (!reserve_string_rule_list(rules, rules->count + 1)) {
        return false;
    }
    safe_copy(rules->items[rules->count].value, sizeof(rules->items[rules->count].value), value);
    lower_ascii(rules->items[rules->count].value);
    rules->count++;
    return true;
}

static bool valid_domain_rule(const char *value);

static bool reserve_app_exact_rule_list(app_exact_rule_list_t *list, int needed) {
    int next_capacity;
    app_exact_rule_t *items;
    if (list == NULL || needed < 0) {
        return false;
    }
    if (list->capacity >= needed) {
        return true;
    }
    next_capacity = list->capacity <= 0 ? INITIAL_REGEX_CAPACITY : list->capacity;
    while (next_capacity < needed) {
        if (next_capacity > INT_MAX / 2) {
            return false;
        }
        next_capacity *= 2;
    }
    items = (app_exact_rule_t *) realloc(list->items,
            (size_t) next_capacity * sizeof(app_exact_rule_t));
    if (items == NULL) {
        return false;
    }
    memset(items + list->capacity, 0,
            (size_t) (next_capacity - list->capacity) * sizeof(app_exact_rule_t));
    list->items = items;
    list->capacity = next_capacity;
    return true;
}

static bool add_app_domain_rule(app_exact_rule_list_t *rules, const char *value) {
    char line[512];
    char *separator;
    char *uid_text;
    char *domain;
    char *end;
    long uid;
    if (rules == NULL || value == NULL || value[0] == '\0') {
        return false;
    }
    safe_copy(line, sizeof(line), value);
    trim(line);
    uid_text = line;
    separator = strchr(line, '|');
    if (separator == NULL) {
        separator = strchr(line, '=');
    }
    if (separator == NULL) {
        separator = line;
        while (*separator && !isspace((unsigned char) *separator) && *separator != ',') {
            separator++;
        }
    }
    if (separator == NULL || *separator == '\0') {
        return false;
    }
    *separator = '\0';
    domain = separator + 1;
    trim(uid_text);
    trim(domain);
    lower_ascii(domain);
    errno = 0;
    uid = strtol(uid_text, &end, 10);
    if (errno != 0 || end == uid_text || *end != '\0' || uid < 0 || uid > INT_MAX
            || !valid_domain_rule(domain)) {
        return false;
    }
    if (!reserve_app_exact_rule_list(rules, rules->count + 1)) {
        return false;
    }
    rules->items[rules->count].uid = (int) uid;
    safe_copy(rules->items[rules->count].domain,
            sizeof(rules->items[rules->count].domain), domain);
    rules->count++;
    return true;
}

static bool reserve_regex_rule_list(regex_rule_list_t *list, int needed) {
    int next_capacity;
    regex_rule_t *items;
    if (list == NULL || needed < 0) {
        return false;
    }
    if (list->capacity >= needed) {
        return true;
    }
    next_capacity = list->capacity <= 0 ? INITIAL_REGEX_CAPACITY : list->capacity;
    while (next_capacity < needed) {
        if (next_capacity > INT_MAX / 2) {
            return false;
        }
        next_capacity *= 2;
    }
    items = (regex_rule_t *) realloc(list->items,
            (size_t) next_capacity * sizeof(regex_rule_t));
    if (items == NULL) {
        return false;
    }
    memset(items + list->capacity, 0,
            (size_t) (next_capacity - list->capacity) * sizeof(regex_rule_t));
    list->items = items;
    list->capacity = next_capacity;
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

static bool add_regex_rule(regex_rule_list_t *rules, const char *value) {
    regex_rule_t *rule;
    if (rules == NULL || value == NULL || value[0] == '\0') {
        return false;
    }
    if (!reserve_regex_rule_list(rules, rules->count + 1)) {
        return false;
    }
    rule = &rules->items[rules->count];
    memset(rule, 0, sizeof(*rule));
    safe_copy(rule->pattern, sizeof(rule->pattern), value);
    /* Compile during reload so malformed regex rules reject the pending generation. */
    if (regcomp(&rule->compiled, value, REG_EXTENDED | REG_NOSUB | REG_ICASE) != 0) {
        memset(rule, 0, sizeof(*rule));
        return false;
    }
    rule->valid = true;
    rules->count++;
    return true;
}

static int choose_exact_index_size(int count) {
    int size = MIN_EXACT_INDEX_SIZE;
    if (count <= 0) {
        return size;
    }
    if (count > MAX_EXACT_INDEX_SIZE / 2) {
        return 0;
    }
    while (size / 2 < count) {
        if (size >= MAX_EXACT_INDEX_SIZE / 2) {
            return count <= MAX_EXACT_INDEX_SIZE / 2 ? MAX_EXACT_INDEX_SIZE : 0;
        }
        size *= 2;
    }
    return size;
}

static bool build_exact_index(const string_rule_list_t *rules, int **index_out, int *index_size_out) {
    int i;
    int index_size;
    int *index;
    if (rules == NULL || index_out == NULL || index_size_out == NULL) {
        return false;
    }
    free(*index_out);
    *index_out = NULL;
    *index_size_out = 0;
    index_size = choose_exact_index_size(rules->count);
    if (index_size <= 0) {
        return false;
    }
    index = (int *) calloc((size_t) index_size, sizeof(int));
    if (index == NULL) {
        return false;
    }
    for (i = 0; i < rules->count; i++) {
        uint32_t slot = hash_domain(rules->items[i].value, 0) % (uint32_t) index_size;
        uint32_t probe;
        for (probe = 0; probe < (uint32_t) index_size; probe++) {
            int existing = index[slot];
            if (existing == 0) {
                index[slot] = i + 1;
                break;
            }
            if (existing > 0 && existing <= rules->count
                    && strcmp(rules->items[existing - 1].value, rules->items[i].value) == 0) {
                break;
            }
            slot = (slot + 1) % (uint32_t) index_size;
        }
        if (probe == (uint32_t) index_size) {
            free(index);
            return false;
        }
    }
    *index_out = index;
    *index_size_out = index_size;
    return true;
}

static bool exact_match_indexed(const string_rule_list_t *rules, const int *index,
                                int index_size, const char *domain) {
    uint32_t slot;
    uint32_t probe;
    if (rules == NULL || index == NULL || index_size <= 0
            || domain == NULL || domain[0] == '\0') {
        return false;
    }
    slot = hash_domain(domain, 0) % (uint32_t) index_size;
    for (probe = 0; probe < (uint32_t) index_size; probe++) {
        int ref = index[slot];
        if (ref == 0) {
            return false;
        }
        if (ref > 0 && ref <= rules->count
                && strcmp(rules->items[ref - 1].value, domain) == 0) {
            return true;
        }
        slot = (slot + 1) % (uint32_t) index_size;
    }
    return false;
}

static uint32_t hash_app_exact_key(int uid, const char *domain) {
    uint32_t h = hash_domain(domain, 0);
    unsigned int value = (unsigned int) uid;
    int i;
    for (i = 0; i < 4; i++) {
        h ^= (uint8_t) ((value >> (i * 8)) & 0xffu);
        h *= 16777619u;
    }
    return h;
}

static bool build_app_exact_index(const app_exact_rule_list_t *rules,
                                  int **index_out, int *index_size_out) {
    int i;
    int index_size;
    int *index;
    if (rules == NULL || index_out == NULL || index_size_out == NULL) {
        return false;
    }
    free(*index_out);
    *index_out = NULL;
    *index_size_out = 0;
    if (rules->count <= 0) {
        return true;
    }
    index_size = choose_exact_index_size(rules->count);
    if (index_size <= 0) {
        return false;
    }
    index = (int *) calloc((size_t) index_size, sizeof(int));
    if (index == NULL) {
        return false;
    }
    for (i = 0; i < rules->count; i++) {
        uint32_t slot = hash_app_exact_key(rules->items[i].uid,
                rules->items[i].domain) % (uint32_t) index_size;
        uint32_t probe;
        for (probe = 0; probe < (uint32_t) index_size; probe++) {
            int existing = index[slot];
            if (existing == 0) {
                index[slot] = i + 1;
                break;
            }
            if (existing > 0 && existing <= rules->count
                    && rules->items[existing - 1].uid == rules->items[i].uid
                    && strcmp(rules->items[existing - 1].domain,
                    rules->items[i].domain) == 0) {
                break;
            }
            slot = (slot + 1) % (uint32_t) index_size;
        }
        if (probe == (uint32_t) index_size) {
            free(index);
            return false;
        }
    }
    *index_out = index;
    *index_size_out = index_size;
    return true;
}

static bool app_exact_match_indexed(const app_exact_rule_list_t *rules, const int *index,
                                    int index_size, int uid, const char *domain) {
    uint32_t slot;
    uint32_t probe;
    if (rules == NULL || index == NULL || index_size <= 0 || uid == UID_UNKNOWN
            || domain == NULL || domain[0] == '\0') {
        return false;
    }
    slot = hash_app_exact_key(uid, domain) % (uint32_t) index_size;
    for (probe = 0; probe < (uint32_t) index_size; probe++) {
        int ref = index[slot];
        if (ref == 0) {
            return false;
        }
        if (ref > 0 && ref <= rules->count
                && rules->items[ref - 1].uid == uid
                && strcmp(rules->items[ref - 1].domain, domain) == 0) {
            return true;
        }
        slot = (slot + 1) % (uint32_t) index_size;
    }
    return false;
}

static bool suffix_trie_reserve(suffix_trie_t *trie, int needed) {
    int next_capacity;
    suffix_trie_node_t *nodes;
    if (trie->capacity >= needed) {
        return true;
    }
    next_capacity = trie->capacity > 0 ? trie->capacity : 64;
    while (next_capacity < needed) {
        if (next_capacity > INT_MAX / 2) {
            return false;
        }
        next_capacity *= 2;
    }
    nodes = (suffix_trie_node_t *) realloc(trie->nodes,
            (size_t) next_capacity * sizeof(suffix_trie_node_t));
    if (nodes == NULL) {
        return false;
    }
    memset(nodes + trie->capacity, 0,
            (size_t) (next_capacity - trie->capacity) * sizeof(suffix_trie_node_t));
    trie->nodes = nodes;
    trie->capacity = next_capacity;
    return true;
}

static bool suffix_trie_init(suffix_trie_t *trie) {
    memset(trie, 0, sizeof(*trie));
    if (!suffix_trie_reserve(trie, 1)) {
        return false;
    }
    trie->count = 1;
    return true;
}

static int suffix_trie_find_child(const suffix_trie_t *trie, int parent, const char *label) {
    int child;
    if (trie == NULL || trie->nodes == NULL || parent < 0 || parent >= trie->count) {
        return -1;
    }
    for (child = trie->nodes[parent].first_child; child != 0;
            child = trie->nodes[child].next_sibling) {
        if (strcmp(trie->nodes[child].label, label) == 0) {
            return child;
        }
    }
    return -1;
}

static int suffix_trie_add_child(suffix_trie_t *trie, int parent, const char *label) {
    int child;
    if (!suffix_trie_reserve(trie, trie->count + 1)) {
        return -1;
    }
    child = trie->count++;
    memset(&trie->nodes[child], 0, sizeof(trie->nodes[child]));
    safe_copy(trie->nodes[child].label, sizeof(trie->nodes[child].label), label);
    trie->nodes[child].next_sibling = trie->nodes[parent].first_child;
    trie->nodes[parent].first_child = child;
    return child;
}

static bool previous_domain_label(const char *domain, size_t *end, char *label,
                                  size_t label_len, bool *done) {
    size_t start;
    size_t len;
    if (domain == NULL || end == NULL || *end == 0 || label == NULL || label_len == 0) {
        return false;
    }
    start = *end;
    while (start > 0 && domain[start - 1] != '.') {
        start--;
    }
    len = *end - start;
    if (len == 0 || len >= label_len) {
        return false;
    }
    memcpy(label, domain + start, len);
    label[len] = '\0';
    if (start == 0) {
        *done = true;
        *end = 0;
    } else {
        *done = false;
        *end = start - 1;
    }
    return true;
}

static bool suffix_trie_insert(suffix_trie_t *trie, const char *suffix) {
    char label[MAX_LABEL];
    size_t end;
    int node = 0;
    bool done = false;
    if (trie == NULL || trie->nodes == NULL || suffix == NULL || suffix[0] == '\0') {
        return false;
    }
    end = strlen(suffix);
    while (!done) {
        int child;
        if (!previous_domain_label(suffix, &end, label, sizeof(label), &done)) {
            return false;
        }
        child = suffix_trie_find_child(trie, node, label);
        if (child < 0) {
            child = suffix_trie_add_child(trie, node, label);
            if (child < 0) {
                return false;
            }
        }
        node = child;
    }
    trie->nodes[node].terminal = true;
    return true;
}

static bool build_suffix_trie(const string_rule_list_t *rules, suffix_trie_t *trie) {
    int i;
    if (rules == NULL) {
        return false;
    }
    free_suffix_trie(trie);
    if (!suffix_trie_init(trie)) {
        return false;
    }
    for (i = 0; i < rules->count; i++) {
        if (!suffix_trie_insert(trie, rules->items[i].value)) {
            free_suffix_trie(trie);
            return false;
        }
    }
    return true;
}

static bool suffix_trie_match(const suffix_trie_t *trie, const char *domain) {
    char label[MAX_LABEL];
    size_t end;
    int node = 0;
    bool done = false;
    if (trie == NULL || trie->nodes == NULL || domain == NULL || domain[0] == '\0') {
        return false;
    }
    end = strlen(domain);
    /* Suffix rules used to scan linearly; this keeps the DNS hot path bounded by label depth. */
    while (!done) {
        int child;
        if (!previous_domain_label(domain, &end, label, sizeof(label), &done)) {
            return false;
        }
        child = suffix_trie_find_child(trie, node, label);
        if (child < 0) {
            return false;
        }
        node = child;
        if (trie->nodes[node].terminal) {
            return true;
        }
    }
    return false;
}

static bool app_suffix_trie_reserve(app_suffix_trie_t *trie, int needed) {
    int next_capacity;
    app_suffix_trie_node_t *nodes;
    if (trie->capacity >= needed) {
        return true;
    }
    next_capacity = trie->capacity > 0 ? trie->capacity : 64;
    while (next_capacity < needed) {
        if (next_capacity > INT_MAX / 2) {
            return false;
        }
        next_capacity *= 2;
    }
    nodes = (app_suffix_trie_node_t *) realloc(trie->nodes,
            (size_t) next_capacity * sizeof(app_suffix_trie_node_t));
    if (nodes == NULL) {
        return false;
    }
    memset(nodes + trie->capacity, 0,
            (size_t) (next_capacity - trie->capacity) * sizeof(app_suffix_trie_node_t));
    trie->nodes = nodes;
    trie->capacity = next_capacity;
    return true;
}

static bool app_suffix_trie_init(app_suffix_trie_t *trie) {
    memset(trie, 0, sizeof(*trie));
    if (!app_suffix_trie_reserve(trie, 1)) {
        return false;
    }
    trie->count = 1;
    return true;
}

static int app_suffix_trie_find_child(const app_suffix_trie_t *trie, int parent,
                                      const char *label) {
    int child;
    if (trie == NULL || trie->nodes == NULL || parent < 0 || parent >= trie->count) {
        return -1;
    }
    for (child = trie->nodes[parent].first_child; child != 0;
            child = trie->nodes[child].next_sibling) {
        if (strcmp(trie->nodes[child].label, label) == 0) {
            return child;
        }
    }
    return -1;
}

static int app_suffix_trie_add_child(app_suffix_trie_t *trie, int parent,
                                     const char *label) {
    int child;
    if (!app_suffix_trie_reserve(trie, trie->count + 1)) {
        return -1;
    }
    child = trie->count++;
    memset(&trie->nodes[child], 0, sizeof(trie->nodes[child]));
    safe_copy(trie->nodes[child].label, sizeof(trie->nodes[child].label), label);
    trie->nodes[child].next_sibling = trie->nodes[parent].first_child;
    trie->nodes[parent].first_child = child;
    return child;
}

static bool app_suffix_trie_node_add_uid(app_suffix_trie_node_t *node, int uid) {
    int next_capacity;
    int *uids;
    int i;
    if (node == NULL || uid == UID_UNKNOWN) {
        return false;
    }
    for (i = 0; i < node->uid_count; i++) {
        if (node->uids[i] == uid) {
            return true;
        }
    }
    if (node->uid_capacity <= node->uid_count) {
        if (node->uid_capacity > INT_MAX / 2) {
            return false;
        }
        next_capacity = node->uid_capacity <= 0 ? 4 : node->uid_capacity * 2;
        if (next_capacity < node->uid_count + 1) {
            next_capacity = node->uid_count + 1;
        }
        uids = (int *) realloc(node->uids, (size_t) next_capacity * sizeof(int));
        if (uids == NULL) {
            return false;
        }
        node->uids = uids;
        node->uid_capacity = next_capacity;
    }
    node->uids[node->uid_count++] = uid;
    return true;
}

static bool app_suffix_trie_node_has_uid(const app_suffix_trie_node_t *node, int uid) {
    int i;
    if (node == NULL || uid == UID_UNKNOWN) {
        return false;
    }
    for (i = 0; i < node->uid_count; i++) {
        if (node->uids[i] == uid) {
            return true;
        }
    }
    return false;
}

static bool app_suffix_trie_insert(app_suffix_trie_t *trie, int uid,
                                   const char *suffix) {
    char label[MAX_LABEL];
    size_t end;
    int node = 0;
    bool done = false;
    if (trie == NULL || trie->nodes == NULL || uid == UID_UNKNOWN
            || suffix == NULL || suffix[0] == '\0') {
        return false;
    }
    end = strlen(suffix);
    while (!done) {
        int child;
        if (!previous_domain_label(suffix, &end, label, sizeof(label), &done)) {
            return false;
        }
        child = app_suffix_trie_find_child(trie, node, label);
        if (child < 0) {
            child = app_suffix_trie_add_child(trie, node, label);
            if (child < 0) {
                return false;
            }
        }
        node = child;
    }
    return app_suffix_trie_node_add_uid(&trie->nodes[node], uid);
}

static bool build_app_suffix_trie(const app_exact_rule_list_t *rules,
                                  app_suffix_trie_t *trie) {
    int i;
    if (rules == NULL) {
        return false;
    }
    free_app_suffix_trie(trie);
    if (!app_suffix_trie_init(trie)) {
        return false;
    }
    for (i = 0; i < rules->count; i++) {
        if (!app_suffix_trie_insert(trie, rules->items[i].uid, rules->items[i].domain)) {
            free_app_suffix_trie(trie);
            return false;
        }
    }
    return true;
}

static bool app_suffix_trie_match(const app_suffix_trie_t *trie, int uid,
                                  const char *domain) {
    char label[MAX_LABEL];
    size_t end;
    int node = 0;
    bool done = false;
    if (trie == NULL || trie->nodes == NULL || uid == UID_UNKNOWN
            || domain == NULL || domain[0] == '\0') {
        return false;
    }
    end = strlen(domain);
    while (!done) {
        int child;
        if (!previous_domain_label(domain, &end, label, sizeof(label), &done)) {
            return false;
        }
        child = app_suffix_trie_find_child(trie, node, label);
        if (child < 0) {
            return false;
        }
        node = child;
        if (app_suffix_trie_node_has_uid(&trie->nodes[node], uid)) {
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

static bool domain_has_suffix(const char *domain, const char *suffix);

static bool domain_has_suffix(const char *domain, const char *suffix) {
    size_t domain_len;
    size_t suffix_len;
    if (domain == NULL || suffix == NULL) {
        return false;
    }
    domain_len = strlen(domain);
    suffix_len = strlen(suffix);
    if (suffix_len == 0 || suffix_len > domain_len) {
        return false;
    }
    if (strcmp(domain + domain_len - suffix_len, suffix) != 0) {
        return false;
    }
    return suffix_len == domain_len || domain[domain_len - suffix_len - 1] == '.';
}

static bool regex_match_rules(const regex_rule_list_t *rules, const char *domain) {
    int i;
    if (rules == NULL || domain == NULL) {
        return false;
    }
    for (i = 0; i < rules->count; i++) {
        if (rules->items[i].valid
                && regexec(&rules->items[i].compiled, domain, 0, NULL, 0) == 0) {
            return true;
        }
    }
    return false;
}

static decision_t evaluate_domain(const config_t *cfg, const char *domain, int uid,
                                  const char **reason) {
    uint64_t now = now_seconds();
    bool temp_allow = temp_match(cfg->temp_allow, cfg->temp_allow_count, domain, now);
    bool app_allow = app_exact_match_indexed(&cfg->app_exact_allow,
            cfg->app_exact_allow_index, cfg->app_exact_allow_index_size, uid, domain);
    bool app_suffix_allow = app_suffix_trie_match(&cfg->app_suffix_allow_trie, uid, domain);
    bool exact_allow = exact_match_indexed(&cfg->exact_allow, cfg->exact_allow_index,
            cfg->exact_allow_index_size, domain);
    bool suffix_allow = suffix_trie_match(&cfg->suffix_allow_trie, domain);
    bool regex_allow = regex_match_rules(&cfg->regex_allow, domain);
    bool block = false;

    if (temp_match(cfg->temp_block, cfg->temp_block_count, domain, now)) {
        *reason = "temp_block";
        block = true;
    } else if (app_exact_match_indexed(&cfg->app_exact_block, cfg->app_exact_block_index,
            cfg->app_exact_block_index_size, uid, domain)) {
        *reason = "app_exact_block";
        block = true;
    } else if (app_suffix_trie_match(&cfg->app_suffix_block_trie, uid, domain)) {
        *reason = "app_suffix_block";
        block = true;
    } else if (exact_match_indexed(&cfg->exact_block, cfg->exact_block_index,
            cfg->exact_block_index_size, domain)) {
        *reason = "exact_block";
        block = true;
    } else if (suffix_trie_match(&cfg->suffix_block_trie, domain)) {
        *reason = "suffix_block";
        block = true;
    } else if (regex_match_rules(&cfg->regex_block, domain)) {
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
    if (app_allow) {
        *reason = "app_exact_allow";
        return DECISION_ALLOW;
    }
    if (app_suffix_allow) {
        *reason = "app_suffix_allow";
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

static void write_u16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t) ((value >> 8) & 0xffu);
    p[1] = (uint8_t) (value & 0xffu);
}

static uint32_t read_u32(const uint8_t *p) {
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | p[3];
}

static void write_u32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t) ((value >> 24) & 0xffu);
    p[1] = (uint8_t) ((value >> 16) & 0xffu);
    p[2] = (uint8_t) ((value >> 8) & 0xffu);
    p[3] = (uint8_t) (value & 0xffu);
}

static uint16_t read_u16(const uint8_t *p) {
    return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

static size_t build_address_response(const uint8_t *query, size_t query_len,
                                     uint8_t *out, size_t out_len,
                                     uint16_t qtype, const char *address) {
    size_t qend = 12;
    size_t pos;
    uint8_t raw[16];
    int family;
    size_t rdlen;
    if (query_len < 12 || address == NULL || address[0] == '\0') {
        return 0;
    }
    while (qend < query_len && query[qend] != 0) {
        uint8_t label_len = query[qend];
        if ((label_len & 0xc0u) != 0 || label_len > 63 || qend + label_len + 1 > query_len) {
            return 0;
        }
        qend += (size_t) label_len + 1;
    }
    if (qend + 5 > query_len) {
        return 0;
    }
    family = qtype == DNS_QTYPE_A ? AF_INET : qtype == DNS_QTYPE_AAAA ? AF_INET6 : AF_UNSPEC;
    if (family == AF_UNSPEC || inet_pton(family, address, raw) != 1) {
        return 0;
    }
    rdlen = qtype == DNS_QTYPE_A ? 4u : 16u;
    if (out_len < qend + 5 + 12 + rdlen) {
        return 0;
    }
    memcpy(out, query, qend + 5);
    out[2] = (uint8_t) (0x80u | (query[2] & 0x01u));
    out[3] = 0x80;
    write_u16(out + 6, 1);
    write_u16(out + 8, 0);
    write_u16(out + 10, 0);
    pos = qend + 5;
    out[pos++] = 0xc0;
    out[pos++] = 0x0c;
    write_u16(out + pos, qtype);
    pos += 2;
    write_u16(out + pos, DNS_CLASS_IN);
    pos += 2;
    write_u32(out + pos, SAFE_SEARCH_TTL);
    pos += 4;
    write_u16(out + pos, (uint16_t) rdlen);
    pos += 2;
    memcpy(out + pos, raw, rdlen);
    return pos + rdlen;
}

static bool domain_equals_or_has_suffix(const char *domain, const char *suffix) {
    return domain != NULL && suffix != NULL && domain_has_suffix(domain, suffix);
}

static bool safe_search_google_tld(const char *suffix) {
    size_t i;
    size_t dots = 0;
    size_t len = suffix == NULL ? 0 : strlen(suffix);
    if (len < 2 || len > 6 || suffix[0] == '.' || suffix[len - 1] == '.') {
        return false;
    }
    for (i = 0; i < len; i++) {
        if (suffix[i] == '.') {
            dots++;
            if (dots > 1 || i == 0 || suffix[i - 1] == '.') {
                return false;
            }
        } else if (!isalpha((unsigned char) suffix[i])) {
            return false;
        }
    }
    return true;
}

static bool safe_search_google_domain(const char *domain) {
    if (domain == NULL) {
        return false;
    }
    if (strncmp(domain, "www.google.", 11) == 0) {
        return safe_search_google_tld(domain + 11);
    }
    if (strncmp(domain, "google.", 7) == 0) {
        return safe_search_google_tld(domain + 7);
    }
    return false;
}

static const safe_search_target_t *safe_search_target_for_domain(const config_t *cfg,
                                                                 const char *domain) {
    if (cfg == NULL || domain == NULL || !cfg->safe_search) {
        return NULL;
    }
    if (safe_search_google_domain(domain)) {
        return &cfg->safe_google;
    }
    if (domain_equals_or_has_suffix(domain, "youtube.com")
            || domain_equals_or_has_suffix(domain, "youtube-nocookie.com")
            || strcmp(domain, "youtube.googleapis.com") == 0
            || strcmp(domain, "youtubei.googleapis.com") == 0) {
        return &cfg->safe_youtube;
    }
    if (strcmp(domain, "bing.com") == 0 || strcmp(domain, "www.bing.com") == 0
            || strcmp(domain, "cn.bing.com") == 0) {
        return &cfg->safe_bing;
    }
    if (strcmp(domain, "duckduckgo.com") == 0 || strcmp(domain, "www.duckduckgo.com") == 0
            || strcmp(domain, "safe.duckduckgo.com") == 0) {
        return &cfg->safe_duckduckgo;
    }
    return NULL;
}

static size_t build_safe_search_response(const config_t *cfg, const char *domain,
                                         uint16_t qtype, const uint8_t *query,
                                         size_t query_len, uint8_t *out, size_t out_len) {
    const safe_search_target_t *target = safe_search_target_for_domain(cfg, domain);
    const char *address;
    if (target == NULL || (qtype != DNS_QTYPE_A && qtype != DNS_QTYPE_AAAA)) {
        return 0;
    }
    address = qtype == DNS_QTYPE_A ? target->ipv4 : target->ipv6;
    if (address[0] == '\0') {
        return 0;
    }
    return build_address_response(query, query_len, out, out_len, qtype, address);
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

static bool read_rr_header(const uint8_t *packet, size_t len, size_t *pos,
                           uint16_t *type, uint32_t *ttl, uint16_t *rdlen,
                           size_t *rdata_pos) {
    size_t rr_pos = skip_name(packet, len, *pos);
    if (rr_pos + 10 > len) {
        return false;
    }
    *type = read_u16(packet + rr_pos);
    *ttl = read_u32(packet + rr_pos + 4);
    *rdlen = read_u16(packet + rr_pos + 8);
    *rdata_pos = rr_pos + 10;
    if (*rdata_pos + *rdlen > len) {
        return false;
    }
    *pos = *rdata_pos + *rdlen;
    return true;
}

static uint32_t clamp_cache_ttl(uint32_t ttl, uint32_t fallback) {
    if (ttl == 0 || ttl == UINT32_MAX) {
        ttl = fallback;
    }
    if (ttl > MAX_CACHE_TTL) {
        ttl = MAX_CACHE_TTL;
    }
    return ttl;
}

static bool response_is_negative_cache(const uint8_t *response, size_t response_len) {
    uint16_t flags;
    uint16_t an;
    uint16_t rcode;
    if (response_len < 12) {
        return false;
    }
    flags = read_u16(response + 2);
    rcode = flags & 0x000fu;
    an = read_u16(response + 6);
    return rcode == 3 || (rcode == 0 && an == 0);
}

static uint32_t extract_cache_ttl(const uint8_t *packet, size_t len, bool negative) {
    uint16_t qd;
    uint16_t an;
    uint16_t ns;
    size_t pos = 12;
    uint16_t i;
    uint32_t min_ttl = UINT32_MAX;
    if (len < 12) {
        return 0;
    }
    qd = read_u16(packet + 4);
    an = read_u16(packet + 6);
    ns = read_u16(packet + 8);
    for (i = 0; i < qd; i++) {
        pos = skip_name(packet, len, pos);
        if (pos + 4 > len) {
            return 0;
        }
        pos += 4;
    }
    for (i = 0; i < an; i++) {
        uint16_t type;
        uint16_t rdlen;
        uint32_t ttl;
        size_t rdata_pos;
        if (!read_rr_header(packet, len, &pos, &type, &ttl, &rdlen, &rdata_pos)) {
            return negative ? DEFAULT_NEGATIVE_TTL : 0;
        }
        if (!negative && ttl < min_ttl) {
            min_ttl = ttl;
        }
    }
    if (!negative) {
        if (min_ttl == 0) {
            return 0;
        }
        return clamp_cache_ttl(min_ttl, DEFAULT_POSITIVE_TTL);
    }
    for (i = 0; i < ns; i++) {
        uint16_t type;
        uint16_t rdlen;
        uint32_t ttl;
        size_t rdata_pos;
        size_t rpos;
        if (!read_rr_header(packet, len, &pos, &type, &ttl, &rdlen, &rdata_pos)) {
            return DEFAULT_NEGATIVE_TTL;
        }
        if (type != 6) {
            continue;
        }
        rpos = skip_name(packet, len, rdata_pos);
        rpos = skip_name(packet, len, rpos);
        if (rpos + 20 <= rdata_pos + rdlen && rpos + 20 <= len) {
            uint32_t minimum = read_u32(packet + rpos + 16);
            uint32_t negative_ttl = ttl < minimum ? ttl : minimum;
            if (negative_ttl < min_ttl) {
                min_ttl = negative_ttl;
            }
        }
    }
    if (min_ttl == 0) {
        return 0;
    }
    return clamp_cache_ttl(min_ttl, DEFAULT_NEGATIVE_TTL);
}

static void rewrite_cached_response_ttls(uint8_t *packet, size_t len, time_t cached_at,
                                         time_t now, uint32_t cache_remaining) {
    uint16_t qd;
    uint32_t total_rrs;
    uint32_t i;
    size_t pos = 12;
    uint64_t elapsed = now > cached_at ? (uint64_t) (now - cached_at) : 0;
    if (packet == NULL || len < 12) {
        return;
    }
    qd = read_u16(packet + 4);
    total_rrs = (uint32_t) read_u16(packet + 6)
            + (uint32_t) read_u16(packet + 8)
            + (uint32_t) read_u16(packet + 10);
    for (i = 0; i < qd; i++) {
        pos = skip_name(packet, len, pos);
        if (pos + 4 > len) {
            return;
        }
        pos += 4;
    }
    for (i = 0; i < total_rrs; i++) {
        size_t rr_pos = skip_name(packet, len, pos);
        size_t ttl_pos = rr_pos + 4;
        size_t rdata_pos = rr_pos + 10;
        uint16_t rdlen;
        uint32_t ttl;
        uint32_t adjusted;
        if (rr_pos + 10 > len) {
            return;
        }
        rdlen = read_u16(packet + rr_pos + 8);
        if (rdata_pos + rdlen > len) {
            return;
        }
        ttl = read_u32(packet + ttl_pos);
        adjusted = ttl > elapsed ? ttl - (uint32_t) elapsed : 0;
        if (adjusted > cache_remaining) {
            adjusted = cache_remaining;
        }
        write_u32(packet + ttl_pos, adjusted);
        pos = rdata_pos + rdlen;
    }
    g_stats.cache_ttl_rewrites++;
}

static bool cache_lookup(const char *domain, uint16_t qtype, const uint8_t *query,
                         uint8_t *out, size_t *out_len, bool *negative) {
    uint32_t h = hash_domain(domain, qtype);
    uint32_t start;
    uint32_t i;
    time_t now = time(NULL);
    if (g_cache == NULL || g_cache_capacity <= 0) {
        return false;
    }
    start = h % (uint32_t) g_cache_capacity;
    for (i = 0; i < (uint32_t) g_cache_capacity; i++) {
        cache_entry_t *entry = &g_cache[(start + i) % (uint32_t) g_cache_capacity];
        if (!entry->used) {
            continue;
        }
        if (entry->hash == h && entry->qtype == qtype && strcmp(entry->domain, domain) == 0) {
            uint32_t remaining;
            uint64_t lifetime_remaining;
            if (entry->expires_at <= now) {
                entry->used = false;
                g_stats.cache_expired++;
                continue;
            }
            lifetime_remaining = (uint64_t) (entry->expires_at - now);
            remaining = lifetime_remaining > (uint64_t) UINT32_MAX
                    ? UINT32_MAX : (uint32_t) lifetime_remaining;
            memcpy(out, entry->response, entry->response_len);
            out[0] = query[0];
            out[1] = query[1];
            *out_len = entry->response_len;
            entry->last_access = now;
            rewrite_cached_response_ttls(out, *out_len, entry->cached_at, now, remaining);
            if (negative != NULL) {
                *negative = entry->negative;
            }
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
    bool negative;
    cache_entry_t *reusable = NULL;
    cache_entry_t *lru = NULL;
    if (g_cache == NULL || g_cache_capacity <= 0
            || response_len < 12 || response_len > MAX_PACKET
            || !response_cacheable(response, response_len)) {
        return;
    }
    negative = response_is_negative_cache(response, response_len);
    ttl = extract_cache_ttl(response, response_len, negative);
    if (ttl == 0) {
        return;
    }
    h = hash_domain(domain, qtype);
    slot = h % (uint32_t) g_cache_capacity;
    entry = NULL;
    for (i = 0; i < (uint32_t) g_cache_capacity; i++) {
        cache_entry_t *candidate = &g_cache[(slot + i) % (uint32_t) g_cache_capacity];
        if (candidate->used && candidate->expires_at <= now) {
            candidate->used = false;
            g_stats.cache_expired++;
        }
        if (candidate->used && candidate->hash == h
                && candidate->qtype == qtype
                && strcmp(candidate->domain, domain) == 0) {
            entry = candidate;
            break;
        }
        if (!candidate->used) {
            if (reusable == NULL) {
                reusable = candidate;
            }
            continue;
        }
        if (lru == NULL || candidate->last_access < lru->last_access) {
            lru = candidate;
        }
    }
    if (entry == NULL) {
        entry = reusable != NULL ? reusable : lru != NULL ? lru : &g_cache[slot];
        evicting = entry->used && entry->expires_at > now;
    }
    if (evicting) {
        g_stats.cache_evictions++;
        g_stats.cache_lru_evictions++;
    }
    memset(entry, 0, sizeof(*entry));
    safe_copy(entry->domain, sizeof(entry->domain), domain);
    entry->qtype = qtype;
    entry->hash = h;
    memcpy(entry->response, response, response_len);
    entry->response_len = response_len;
    entry->cached_at = now;
    entry->last_access = now;
    entry->expires_at = now + ttl;
    entry->used = true;
    entry->negative = negative;
    g_stats.cache_stores++;
    if (negative) {
        g_stats.cache_negative_stores++;
    } else {
        g_stats.cache_positive_stores++;
    }
}

static bool cache_insert_existing(cache_entry_t *cache, int capacity,
                                  const cache_entry_t *source, time_t now) {
    uint32_t slot;
    uint32_t i;
    cache_entry_t *entry = NULL;
    cache_entry_t *reusable = NULL;
    cache_entry_t *lru = NULL;
    if (cache == NULL || capacity <= 0 || source == NULL || !source->used
            || source->expires_at <= now || source->response_len == 0
            || source->response_len > MAX_PACKET) {
        return false;
    }
    slot = source->hash % (uint32_t) capacity;
    for (i = 0; i < (uint32_t) capacity; i++) {
        cache_entry_t *candidate = &cache[(slot + i) % (uint32_t) capacity];
        if (candidate->used && candidate->expires_at <= now) {
            candidate->used = false;
        }
        if (candidate->used && candidate->hash == source->hash
                && candidate->qtype == source->qtype
                && strcmp(candidate->domain, source->domain) == 0) {
            entry = candidate;
            break;
        }
        if (!candidate->used) {
            if (reusable == NULL) {
                reusable = candidate;
            }
            continue;
        }
        if (lru == NULL || candidate->last_access < lru->last_access) {
            lru = candidate;
        }
    }
    if (entry == NULL) {
        entry = reusable != NULL ? reusable : lru != NULL ? lru : &cache[slot];
    }
    *entry = *source;
    entry->used = true;
    return true;
}

static int cache_count_entries_in(const cache_entry_t *cache, int capacity, time_t now) {
    int i;
    int count = 0;
    if (cache == NULL || capacity <= 0) {
        return 0;
    }
    for (i = 0; i < capacity; i++) {
        if (cache[i].used && cache[i].expires_at > now) {
            count++;
        }
    }
    return count;
}

static void migrate_cache_entries(cache_entry_t *old_cache, int old_capacity,
                                  cache_entry_t *new_cache, int new_capacity) {
    int i;
    int candidates = 0;
    int preserved;
    time_t now = time(NULL);
    if (old_cache == NULL || old_capacity <= 0) {
        return;
    }
    if (new_cache == NULL || new_capacity <= 0) {
        g_stats.cache_reload_dropped += (uint64_t) cache_count_entries_in(old_cache,
                old_capacity, now);
        return;
    }
    for (i = 0; i < old_capacity; i++) {
        if (old_cache[i].used && old_cache[i].expires_at > now) {
            candidates++;
            cache_insert_existing(new_cache, new_capacity, &old_cache[i], now);
        }
    }
    preserved = cache_count_entries_in(new_cache, new_capacity, now);
    g_stats.cache_reload_preserved += (uint64_t) preserved;
    if (candidates > preserved) {
        g_stats.cache_reload_dropped += (uint64_t) (candidates - preserved);
    }
}

static uint64_t hash_scope_u64(uint64_t hash, uint64_t value) {
    int i;
    for (i = 0; i < 8; i++) {
        hash ^= (uint8_t) ((value >> (i * 8)) & 0xffu);
        hash *= 1099511628211ULL;
    }
    return hash;
}

static uint64_t hash_scope_string(uint64_t hash, const char *value) {
    const unsigned char *p = (const unsigned char *) (value == NULL ? "" : value);
    while (*p) {
        hash ^= *p++;
        hash *= 1099511628211ULL;
    }
    return hash_scope_u64(hash, 0xffu);
}

static uint64_t hash_scope_upstream(uint64_t hash, const upstream_t *upstream) {
    if (upstream == NULL) {
        return hash_scope_u64(hash, 0);
    }
    hash = hash_scope_string(hash, upstream->host);
    hash = hash_scope_u64(hash, (uint64_t) upstream->port);
    hash = hash_scope_u64(hash, (uint64_t) upstream->protocol);
    return hash;
}

static uint64_t compute_resolver_scope_hash(const config_t *cfg) {
    int i;
    uint64_t hash = 1469598103934665603ULL;
    if (cfg == NULL) {
        return hash;
    }
    hash = hash_scope_u64(hash, (uint64_t) cfg->upstream_count);
    for (i = 0; i < cfg->upstream_count; i++) {
        hash = hash_scope_upstream(hash, &cfg->upstreams[i]);
    }
    hash = hash_scope_u64(hash, (uint64_t) cfg->split_upstream_count);
    for (i = 0; i < cfg->split_upstream_count; i++) {
        hash = hash_scope_string(hash, cfg->split_upstreams[i].suffix);
        hash = hash_scope_upstream(hash, &cfg->split_upstreams[i].upstream);
    }
    return hash;
}

static void compile_upstream_address(upstream_t *upstream) {
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;
    if (upstream == NULL || upstream->host[0] == '\0') {
        return;
    }
    memset(&upstream->addr, 0, sizeof(upstream->addr));
    upstream->addr_len = 0;
    addr4 = (struct sockaddr_in *) &upstream->addr;
    if (inet_pton(AF_INET, upstream->host, &addr4->sin_addr) == 1) {
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons((uint16_t) upstream->port);
        upstream->addr_len = sizeof(*addr4);
        return;
    }
    addr6 = (struct sockaddr_in6 *) &upstream->addr;
    if (inet_pton(AF_INET6, upstream->host, &addr6->sin6_addr) == 1) {
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons((uint16_t) upstream->port);
        upstream->addr_len = sizeof(*addr6);
    }
}

static void init_upstream_runtime(upstream_t *upstream) {
    if (upstream != NULL) {
        upstream->udp_fd = -1;
    }
}

static void set_socket_timeout(int fd, int timeout_ms) {
    struct timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

static void set_socket_buffers(int fd) {
    int size = DNS_SOCKET_BUFFER_BYTES;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
}

static bool socket_timed_out(void) {
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT;
}

static int connect_upstream(const upstream_t *upstream, int socktype, int timeout_ms) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *rp;
    char port[16];
    int fd = -1;
    if (upstream == NULL) {
        return -1;
    }
    if (upstream->addr_len > 0) {
        fd = socket(upstream->addr.ss_family, socktype, 0);
        if (fd < 0) {
            return -1;
        }
        set_socket_buffers(fd);
        set_socket_timeout(fd, timeout_ms);
        if (connect(fd, (const struct sockaddr *) &upstream->addr, upstream->addr_len) == 0) {
            return fd;
        }
        close(fd);
        return -1;
    }
    snprintf(port, sizeof(port), "%d", upstream->port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    if (getaddrinfo(upstream->host, port, &hints, &res) != 0) {
        return -1;
    }
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }
        set_socket_buffers(fd);
        set_socket_timeout(fd, timeout_ms);
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static void prepare_udp_upstream_socket(upstream_t *upstream, int timeout_ms) {
    if (upstream == NULL || upstream->protocol == UPSTREAM_PROTO_TCP || upstream->addr_len <= 0) {
        return;
    }
    upstream->udp_fd = connect_upstream(upstream, SOCK_DGRAM, timeout_ms);
}

static void prepare_udp_upstream_sockets(config_t *cfg) {
    int i;
    if (cfg == NULL) {
        return;
    }
    for (i = 0; i < cfg->upstream_count; i++) {
        prepare_udp_upstream_socket(&cfg->upstreams[i], cfg->timeout_ms);
    }
    for (i = 0; i < cfg->split_upstream_count; i++) {
        prepare_udp_upstream_socket(&cfg->split_upstreams[i].upstream, cfg->timeout_ms);
    }
}

static const char *upstream_protocol_name(upstream_protocol_t protocol) {
    switch (protocol) {
        case UPSTREAM_PROTO_UDP:
            return "udp";
        case UPSTREAM_PROTO_TCP:
            return "tcp";
        case UPSTREAM_PROTO_AUTO:
        default:
            return "auto";
    }
}

static const upstream_t *select_upstreams(const config_t *cfg, const char *domain,
                                          int *count, const char **route) {
    int i;
    int best = -1;
    size_t best_len = 0;
    for (i = 0; i < cfg->split_upstream_count; i++) {
        size_t suffix_len = strlen(cfg->split_upstreams[i].suffix);
        if (suffix_len > best_len && domain_has_suffix(domain, cfg->split_upstreams[i].suffix)) {
            best = i;
            best_len = suffix_len;
        }
    }
    if (best >= 0) {
        *count = 1;
        if (route != NULL) {
            *route = "split_upstream";
        }
        return &cfg->split_upstreams[best].upstream;
    }
    *count = cfg->upstream_count;
    if (route != NULL) {
        *route = "upstream";
    }
    return cfg->upstreams;
}

static int compiled_upstream_address_count(const config_t *cfg) {
    int i;
    int count = 0;
    if (cfg == NULL) {
        return 0;
    }
    for (i = 0; i < cfg->upstream_count; i++) {
        if (cfg->upstreams[i].addr_len > 0) {
            count++;
        }
    }
    for (i = 0; i < cfg->split_upstream_count; i++) {
        if (cfg->split_upstreams[i].upstream.addr_len > 0) {
            count++;
        }
    }
    return count;
}

static int reusable_udp_upstream_socket_count(const config_t *cfg) {
    int i;
    int count = 0;
    if (cfg == NULL) {
        return 0;
    }
    for (i = 0; i < cfg->upstream_count; i++) {
        if (cfg->upstreams[i].udp_fd >= 0) {
            count++;
        }
    }
    for (i = 0; i < cfg->split_upstream_count; i++) {
        if (cfg->split_upstreams[i].upstream.udp_fd >= 0) {
            count++;
        }
    }
    return count;
}

static bool dns_response_truncated(const uint8_t *response, size_t response_len);
static ssize_t forward_tcp_to_upstream(const upstream_t *upstream, int timeout_ms,
                                       const uint8_t *query, size_t query_len,
                                       uint8_t *response, size_t response_len);
static ssize_t forward_udp_to_upstream(const upstream_t *upstream, int timeout_ms,
                                       const uint8_t *query, size_t query_len,
                                       uint8_t *response, size_t response_len);

static ssize_t forward_udp(const config_t *cfg, const char *domain, const uint8_t *query,
                           size_t query_len, uint8_t *response, size_t response_len,
                           const char **route) {
    int i;
    int count = 0;
    uint8_t truncated_response[MAX_PACKET];
    ssize_t truncated_len = -1;
    bool split_route = false;
    const upstream_t *upstreams = select_upstreams(cfg, domain, &count, route);
    split_route = route != NULL && *route != NULL && strcmp(*route, "split_upstream") == 0;
    for (i = 0; i < count; i++) {
        bool udp_only = upstreams[i].protocol == UPSTREAM_PROTO_UDP;
        ssize_t got;
        if (upstreams[i].protocol == UPSTREAM_PROTO_TCP) {
            got = forward_tcp_to_upstream(&upstreams[i], cfg->timeout_ms,
                    query, query_len, response, response_len);
            if (got > 0) {
                if (route != NULL) {
                    *route = split_route ? "split_upstream_tcp" : "upstream_tcp";
                }
                return got;
            }
            continue;
        }
        got = forward_udp_to_upstream(&upstreams[i], cfg->timeout_ms,
                query, query_len, response, response_len);
        if (got > 0) {
            if (dns_response_truncated(response, (size_t) got)) {
                ssize_t tcp_got;
                g_stats.upstream_truncated_responses++;
                if (udp_only) {
                    if (route != NULL) {
                        *route = split_route ? "split_upstream_udp" : "upstream_udp";
                    }
                    return got;
                }
                if (truncated_len < 0 && (size_t) got <= sizeof(truncated_response)) {
                    memcpy(truncated_response, response, (size_t) got);
                    truncated_len = got;
                }
                tcp_got = forward_tcp_to_upstream(&upstreams[i], cfg->timeout_ms,
                        query, query_len, response, response_len);
                if (tcp_got > 0) {
                    g_stats.upstream_tcp_fallbacks++;
                    if (route != NULL) {
                        *route = split_route ? "split_upstream_tcp_fallback" : "upstream_tcp_fallback";
                    }
                    return tcp_got;
                }
                continue;
            }
            if (udp_only && route != NULL) {
                *route = split_route ? "split_upstream_udp" : "upstream_udp";
            }
            return got;
        }
    }
    if (truncated_len > 0) {
        memcpy(response, truncated_response, (size_t) truncated_len);
        return truncated_len;
    }
    return -1;
}

static ssize_t forward_udp_to_upstream(const upstream_t *upstream, int timeout_ms,
                                       const uint8_t *query, size_t query_len,
                                       uint8_t *response, size_t response_len) {
    int fd;
    ssize_t got;
    bool close_fd = false;
    if (upstream == NULL) {
        return -1;
    }
    fd = upstream->udp_fd;
    if (fd < 0) {
        fd = connect_upstream(upstream, SOCK_DGRAM, timeout_ms);
        close_fd = true;
    } else {
        set_socket_timeout(fd, timeout_ms);
        g_stats.upstream_udp_socket_reuses++;
    }
    if (fd < 0) {
        return -1;
    }
    if (send(fd, query, query_len, 0) < 0) {
        if (close_fd) {
            close(fd);
        }
        return -1;
    }
    do {
        got = recv(fd, response, response_len, 0);
        if (got < 2 || query_len < 2
                || (response[0] == query[0] && response[1] == query[1])) {
            break;
        }
        g_stats.upstream_udp_stale_replies++;
    } while (got > 0);
    if (got >= 2 && query_len >= 2 && (response[0] != query[0] || response[1] != query[1])) {
        got = -1;
    }
    if (close_fd) {
        close(fd);
    }
    return got;
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
        ssize_t got = cfg->upstreams[i].protocol == UPSTREAM_PROTO_TCP
                ? forward_tcp_to_upstream(&cfg->upstreams[i], timeout_ms,
                query, query_len, response, response_len)
                : forward_udp_to_upstream(&cfg->upstreams[i], timeout_ms,
                query, query_len, response, response_len);
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
    if (upstream->protocol == UPSTREAM_PROTO_TCP) {
        return forward_tcp_to_upstream(upstream, timeout_ms, query, query_len,
                response, response_len);
    }
    return forward_udp_to_upstream(upstream, timeout_ms, query, query_len,
            response, response_len);
}

static bool dns_response_truncated(const uint8_t *response, size_t response_len) {
    return response_len >= 4 && (response[2] & 0x02u) != 0;
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

static ssize_t forward_tcp_to_upstream(const upstream_t *upstream, int timeout_ms,
                                       const uint8_t *query, size_t query_len,
                                       uint8_t *response, size_t response_len) {
    uint8_t lenbuf[2];
    uint8_t rlenbuf[2];
    uint16_t rlen;
    int fd;
    if (query_len > 65535) {
        return -1;
    }
    lenbuf[0] = (uint8_t) ((query_len >> 8) & 0xffu);
    lenbuf[1] = (uint8_t) (query_len & 0xffu);
    fd = connect_upstream(upstream, SOCK_STREAM, timeout_ms);
    if (fd < 0) {
        return -1;
    }
    if (send(fd, lenbuf, 2, 0) != 2 || send(fd, query, query_len, 0) != (ssize_t) query_len) {
        close(fd);
        return -1;
    }
    if (read_full(fd, rlenbuf, 2) != 2) {
        close(fd);
        return -1;
    }
    rlen = (uint16_t) ((rlenbuf[0] << 8) | rlenbuf[1]);
    if (rlen == 0 || rlen > response_len) {
        close(fd);
        return -1;
    }
    if (read_full(fd, response, rlen) != rlen) {
        close(fd);
        return -1;
    }
    close(fd);
    return rlen;
}

static ssize_t forward_tcp(const config_t *cfg, const char *domain, const uint8_t *query,
                           size_t query_len, uint8_t *response, size_t response_len,
                           const char **route) {
    int i;
    int count = 0;
    bool split_route = false;
    const upstream_t *upstreams;
    if (query_len > 65535) {
        return -1;
    }
    upstreams = select_upstreams(cfg, domain, &count, route);
    split_route = route != NULL && *route != NULL && strcmp(*route, "split_upstream") == 0;
    for (i = 0; i < count; i++) {
        ssize_t got = upstreams[i].protocol == UPSTREAM_PROTO_UDP
                ? forward_udp_to_upstream(&upstreams[i], cfg->timeout_ms,
                query, query_len, response, response_len)
                : forward_tcp_to_upstream(&upstreams[i], cfg->timeout_ms,
                query, query_len, response, response_len);
        if (got > 0) {
            if (route != NULL) {
                if (upstreams[i].protocol == UPSTREAM_PROTO_UDP) {
                    *route = split_route ? "split_upstream_udp" : "upstream_udp";
                } else if (upstreams[i].protocol == UPSTREAM_PROTO_TCP) {
                    *route = split_route ? "split_upstream_tcp" : "upstream_tcp";
                }
            }
            return got;
        }
    }
    return -1;
}

static void default_config(config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->listen_port = DEFAULT_PORT;
    cfg->fail_open = 1;
    cfg->timeout_ms = DEFAULT_TIMEOUT_MS;
    cfg->cache_size = DEFAULT_CACHE_SIZE;
    cfg->query_logging = 1;
    cfg->persist_query_logs = 1;
    safe_copy(cfg->control_socket, sizeof(cfg->control_socket), "/data/local/tmp/afwall_dnsd.sock");
    cfg->upstream_count = 1;
    init_upstream_runtime(&cfg->upstreams[0]);
    safe_copy(cfg->upstreams[0].host, sizeof(cfg->upstreams[0].host), "1.1.1.1");
    cfg->upstreams[0].port = 53;
    cfg->upstreams[0].protocol = UPSTREAM_PROTO_AUTO;
    compile_upstream_address(&cfg->upstreams[0]);
}

static bool parse_upstream_value(const char *value, upstream_t *upstream) {
    char line[256];
    char *target;
    char *first_colon;
    char *last_colon;
    if (value == NULL || value[0] == '\0' || upstream == NULL) {
        return false;
    }
    memset(upstream, 0, sizeof(*upstream));
    init_upstream_runtime(upstream);
    upstream->protocol = UPSTREAM_PROTO_AUTO;
    upstream->port = 53;
    safe_copy(line, sizeof(line), value);
    trim(line);
    target = line;
    if (strncmp(target, "udp://", 6) == 0) {
        upstream->protocol = UPSTREAM_PROTO_UDP;
        target += 6;
    } else if (strncmp(target, "tcp://", 6) == 0) {
        upstream->protocol = UPSTREAM_PROTO_TCP;
        target += 6;
    } else if (strstr(target, "://") != NULL) {
        return false;
    }
    trim(target);
    if (target[0] == '[') {
        char *end = strchr(target, ']');
        if (end == NULL || end == target + 1) {
            return false;
        }
        *end = '\0';
        safe_copy(upstream->host, sizeof(upstream->host), target + 1);
        if (end[1] == ':' && end[2] != '\0') {
            upstream->port = atoi(end + 2);
        }
    } else {
        first_colon = strchr(target, ':');
        last_colon = strrchr(target, ':');
        if (first_colon != NULL && first_colon == last_colon && first_colon[1] != '\0') {
            *first_colon = '\0';
            safe_copy(upstream->host, sizeof(upstream->host), target);
            upstream->port = atoi(first_colon + 1);
        } else {
            safe_copy(upstream->host, sizeof(upstream->host), target);
        }
    }
    trim(upstream->host);
    if (upstream->port <= 0 || upstream->port > 65535) {
        upstream->port = 53;
    }
    if (upstream->host[0] == '\0') {
        return false;
    }
    compile_upstream_address(upstream);
    return true;
}

static bool parse_upstream(config_t *cfg, const char *value) {
    if (cfg->upstream_count >= MAX_UPSTREAMS) {
        return false;
    }
    if (!parse_upstream_value(value, &cfg->upstreams[cfg->upstream_count])) {
        return false;
    }
    cfg->upstream_count++;
    return true;
}

static bool parse_split_upstream(config_t *cfg, const char *value) {
    char line[512];
    char *sep;
    char *suffix;
    char *upstream;
    if (cfg->split_upstream_count >= MAX_SPLIT_UPSTREAMS || value == NULL || value[0] == '\0') {
        return false;
    }
    safe_copy(line, sizeof(line), value);
    sep = strchr(line, '|');
    if (sep == NULL) {
        sep = strchr(line, '=');
    }
    if (sep == NULL) {
        sep = strchr(line, ' ');
    }
    if (sep == NULL) {
        return false;
    }
    *sep = '\0';
    suffix = line;
    upstream = sep + 1;
    trim(suffix);
    trim(upstream);
    lower_ascii(suffix);
    if (suffix[0] == '*' && suffix[1] == '.') {
        memmove(suffix, suffix + 2, strlen(suffix + 2) + 1);
    }
    while (suffix[0] == '.') {
        memmove(suffix, suffix + 1, strlen(suffix));
    }
    if (!valid_domain_rule(suffix)) {
        return false;
    }
    safe_copy(cfg->split_upstreams[cfg->split_upstream_count].suffix,
            sizeof(cfg->split_upstreams[cfg->split_upstream_count].suffix), suffix);
    if (!parse_upstream_value(upstream, &cfg->split_upstreams[cfg->split_upstream_count].upstream)) {
        return false;
    }
    cfg->split_upstream_count++;
    return true;
}

static safe_search_target_t *safe_search_target_by_name(config_t *cfg, const char *provider) {
    if (cfg == NULL || provider == NULL) {
        return NULL;
    }
    if (strcmp(provider, "google") == 0) {
        return &cfg->safe_google;
    }
    if (strcmp(provider, "youtube") == 0) {
        return &cfg->safe_youtube;
    }
    if (strcmp(provider, "bing") == 0) {
        return &cfg->safe_bing;
    }
    if (strcmp(provider, "duckduckgo") == 0) {
        return &cfg->safe_duckduckgo;
    }
    return NULL;
}

static void parse_safe_search_address(config_t *cfg, const char *value) {
    char line[256];
    char *sep;
    char *provider;
    char *address;
    safe_search_target_t *target;
    struct in_addr addr4;
    struct in6_addr addr6;
    if (cfg == NULL || value == NULL || value[0] == '\0') {
        return;
    }
    safe_copy(line, sizeof(line), value);
    sep = strchr(line, '|');
    if (sep == NULL) {
        sep = strchr(line, '=');
    }
    if (sep == NULL) {
        return;
    }
    *sep = '\0';
    provider = line;
    address = sep + 1;
    trim(provider);
    trim(address);
    lower_ascii(provider);
    target = safe_search_target_by_name(cfg, provider);
    if (target == NULL || address[0] == '\0') {
        return;
    }
    if (inet_pton(AF_INET, address, &addr4) == 1) {
        safe_copy(target->ipv4, sizeof(target->ipv4), address);
    } else if (inet_pton(AF_INET6, address, &addr6) == 1) {
        safe_copy(target->ipv6, sizeof(target->ipv6), address);
    }
}

static bool load_string_rule_file(string_rule_list_t *rules, const char *path);
static bool load_regex_rule_file(regex_rule_list_t *rules, const char *path);

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
        } else if (strcmp(key, "heartbeat_file") == 0) {
            safe_copy(new_cfg->heartbeat_file, sizeof(new_cfg->heartbeat_file), value);
        } else if (strcmp(key, "fail_open") == 0) {
            new_cfg->fail_open = atoi(value) != 0;
        } else if (strcmp(key, "strict_mode") == 0) {
            new_cfg->strict_mode = atoi(value) != 0;
        } else if (strcmp(key, "timeout_ms") == 0) {
            int timeout = atoi(value);
            if (timeout >= 250 && timeout <= 10000) {
                new_cfg->timeout_ms = timeout;
            }
        } else if (strcmp(key, "cache_size") == 0) {
            int cache_size = atoi(value);
            if (cache_size >= 0 && cache_size <= MAX_CACHE_SIZE) {
                new_cfg->cache_size = cache_size;
            }
        } else if (strcmp(key, "query_logging") == 0) {
            new_cfg->query_logging = config_bool_value(value);
        } else if (strcmp(key, "persist_query_logs") == 0) {
            new_cfg->persist_query_logs = config_bool_value(value);
        } else if (strcmp(key, "safe_search") == 0) {
            new_cfg->safe_search = config_bool_value(value);
        } else if (strcmp(key, "safe_search_address") == 0) {
            parse_safe_search_address(new_cfg, value);
        } else if (strcmp(key, "upstream") == 0) {
            parse_upstream(new_cfg, value);
        } else if (strcmp(key, "split_upstream") == 0) {
            parse_split_upstream(new_cfg, value);
        } else if (strcmp(key, "allow_exact") == 0) {
            if (!add_string_rule(&new_cfg->exact_allow, value)) {
                fclose(fp);
                return false;
            }
        } else if (strcmp(key, "allow_exact_file") == 0) {
            if (!load_string_rule_file(&new_cfg->exact_allow, value)) {
                fclose(fp);
                return false;
            }
        } else if (strcmp(key, "allow_suffix") == 0) {
            if (!add_string_rule(&new_cfg->suffix_allow, value)) {
                fclose(fp);
                return false;
            }
        } else if (strcmp(key, "allow_suffix_file") == 0) {
            if (!load_string_rule_file(&new_cfg->suffix_allow, value)) {
                fclose(fp);
                return false;
            }
        } else if (strcmp(key, "block_exact") == 0) {
            if (!add_string_rule(&new_cfg->exact_block, value)) {
                fclose(fp);
                return false;
            }
        } else if (strcmp(key, "block_exact_file") == 0) {
            if (!load_string_rule_file(&new_cfg->exact_block, value)) {
                fclose(fp);
                return false;
            }
        } else if (strcmp(key, "block_suffix") == 0) {
            if (!add_string_rule(&new_cfg->suffix_block, value)) {
                fclose(fp);
                return false;
            }
        } else if (strcmp(key, "block_suffix_file") == 0) {
            if (!load_string_rule_file(&new_cfg->suffix_block, value)) {
                fclose(fp);
                return false;
            }
        } else if (strcmp(key, "app_allow_exact") == 0) {
            if (!add_app_domain_rule(&new_cfg->app_exact_allow, value)) {
                fclose(fp);
                return false;
            }
        } else if (strcmp(key, "app_block_exact") == 0) {
            if (!add_app_domain_rule(&new_cfg->app_exact_block, value)) {
                fclose(fp);
                return false;
            }
        } else if (strcmp(key, "app_allow_suffix") == 0) {
            if (!add_app_domain_rule(&new_cfg->app_suffix_allow, value)) {
                fclose(fp);
                return false;
            }
        } else if (strcmp(key, "app_block_suffix") == 0) {
            if (!add_app_domain_rule(&new_cfg->app_suffix_block, value)) {
                fclose(fp);
                return false;
            }
        } else if (strcmp(key, "allow_regex") == 0) {
            if (!add_regex_rule(&new_cfg->regex_allow, value)) {
                fclose(fp);
                return false;
            }
        } else if (strcmp(key, "allow_regex_file") == 0) {
            if (!load_regex_rule_file(&new_cfg->regex_allow, value)) {
                fclose(fp);
                return false;
            }
        } else if (strcmp(key, "block_regex") == 0) {
            if (!add_regex_rule(&new_cfg->regex_block, value)) {
                fclose(fp);
                return false;
            }
        } else if (strcmp(key, "block_regex_file") == 0) {
            if (!load_regex_rule_file(&new_cfg->regex_block, value)) {
                fclose(fp);
                return false;
            }
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
        new_cfg->upstreams[0].protocol = UPSTREAM_PROTO_AUTO;
        compile_upstream_address(&new_cfg->upstreams[0]);
        new_cfg->upstream_count = 1;
    }
    if (!build_exact_index(&new_cfg->exact_allow, &new_cfg->exact_allow_index,
            &new_cfg->exact_allow_index_size)
            || !build_exact_index(&new_cfg->exact_block, &new_cfg->exact_block_index,
            &new_cfg->exact_block_index_size)
            || !build_app_exact_index(&new_cfg->app_exact_allow,
            &new_cfg->app_exact_allow_index, &new_cfg->app_exact_allow_index_size)
            || !build_app_exact_index(&new_cfg->app_exact_block,
            &new_cfg->app_exact_block_index, &new_cfg->app_exact_block_index_size)
            || !build_suffix_trie(&new_cfg->suffix_allow, &new_cfg->suffix_allow_trie)
            || !build_suffix_trie(&new_cfg->suffix_block, &new_cfg->suffix_block_trie)
            || !build_app_suffix_trie(&new_cfg->app_suffix_allow,
            &new_cfg->app_suffix_allow_trie)
            || !build_app_suffix_trie(&new_cfg->app_suffix_block,
            &new_cfg->app_suffix_block_trie)) {
        return false;
    }
    prepare_udp_upstream_sockets(new_cfg);
    new_cfg->resolver_scope_hash = compute_resolver_scope_hash(new_cfg);
    new_cfg->generation = g_cfg.generation + 1;
    return true;
}

static bool load_string_rule_file(string_rule_list_t *rules, const char *path) {
    FILE *fp;
    char line[1024];
    if (path == NULL || path[0] == '\0') {
        return true;
    }
    fp = fopen(path, "r");
    if (fp == NULL) {
        return true;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        trim(line);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        if (!add_string_rule(rules, line)) {
            fclose(fp);
            return false;
        }
    }
    fclose(fp);
    return true;
}

static bool load_regex_rule_file(regex_rule_list_t *rules, const char *path) {
    FILE *fp;
    char line[1024];
    if (path == NULL || path[0] == '\0') {
        return true;
    }
    fp = fopen(path, "r");
    if (fp == NULL) {
        return true;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        trim(line);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        if (!add_regex_rule(rules, line)) {
            fclose(fp);
            return false;
        }
    }
    fclose(fp);
    return true;
}

static bool reload_config(void) {
    config_t *next = (config_t *) calloc(1, sizeof(config_t));
    cache_entry_t *next_cache = NULL;
    if (next == NULL) {
        return false;
    }
    if (!load_config(g_config_path, next)) {
        free_config_dynamic(next);
        free(next);
        return false;
    }
    if (next->cache_size > 0) {
        next_cache = (cache_entry_t *) calloc((size_t) next->cache_size, sizeof(cache_entry_t));
        if (next_cache == NULL) {
            free_config_dynamic(next);
            free(next);
            return false;
        }
    }
    if (g_cache != NULL && g_cache_capacity > 0) {
        if (g_cfg.resolver_scope_hash == next->resolver_scope_hash) {
            migrate_cache_entries(g_cache, g_cache_capacity, next_cache, next->cache_size);
        } else {
            g_stats.cache_reload_scope_changes++;
            g_stats.cache_reload_dropped += (uint64_t) cache_count_entries_in(g_cache,
                    g_cache_capacity, time(NULL));
        }
    }
    free_config_dynamic(&g_cfg);
    g_cfg = *next;
    free(next);
    free(g_cache);
    g_cache = next_cache;
    g_cache_capacity = g_cfg.cache_size;
    set_log_output(g_cfg.log_file, g_cfg.persist_query_logs != 0);
    if (!g_cfg.query_logging) {
        clear_log_ring();
    }
    g_stats.reloads++;
    return true;
}

static void write_validate_response(int client) {
    config_t *candidate = (config_t *) calloc(1, sizeof(config_t));
    if (candidate == NULL) {
        write_control_response(client,
                "validate=0\nstatus=allocation_failed\nactive_generation=%llu\n",
                (unsigned long long) g_cfg.generation);
        return;
    }
    if (!load_config(g_config_path, candidate)) {
        free_config_dynamic(candidate);
        free(candidate);
        write_control_response(client,
                "validate=0\nstatus=config_rejected\nactive_generation=%llu\n",
                (unsigned long long) g_cfg.generation);
        return;
    }
    write_control_response(client,
            "validate=1\nstatus=ok\nactive_generation=%llu\ncandidate_generation=%llu\n"
            "upstreams=%d\nsplit_upstreams=%d\n"
            "rules_exact_allow=%d\nrules_suffix_allow=%d\n"
            "rules_exact_block=%d\nrules_suffix_block=%d\n"
            "rules_app_exact_allow=%d\nrules_app_exact_block=%d\n"
            "rules_app_suffix_allow=%d\nrules_app_suffix_block=%d\n"
            "rules_regex_allow=%d\nrules_regex_block=%d\n"
            "rules_temp_allow=%d\nrules_temp_block=%d\n"
            "cache_size=%d\nresolver_scope_hash=%llu\n",
            (unsigned long long) g_cfg.generation,
            (unsigned long long) candidate->generation,
            candidate->upstream_count,
            candidate->split_upstream_count,
            candidate->exact_allow.count,
            candidate->suffix_allow.count,
            candidate->exact_block.count,
            candidate->suffix_block.count,
            candidate->app_exact_allow.count,
            candidate->app_exact_block.count,
            candidate->app_suffix_allow.count,
            candidate->app_suffix_block.count,
            candidate->regex_allow.count,
            candidate->regex_block.count,
            candidate->temp_allow_count,
            candidate->temp_block_count,
            candidate->cache_size,
            (unsigned long long) candidate->resolver_scope_hash);
    free_config_dynamic(candidate);
    free(candidate);
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

static void write_heartbeat_file(void) {
    FILE *fp;
    if (g_cfg.heartbeat_file[0] == '\0') {
        return;
    }
    fp = fopen(g_cfg.heartbeat_file, "w");
    if (fp != NULL) {
        fprintf(fp, "%llu\n", (unsigned long long) now_seconds());
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
    set_socket_buffers(fd);
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
    set_socket_buffers(fd);
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

static void finish_dns_query(const char *domain, const char *action, const char *transport,
                             const char *source, int uid, uint16_t qtype,
                             const char *result, const char *rule,
                             const char *upstream, const struct timeval *start) {
    struct timeval end;
    int latency_ms;
    gettimeofday(&end, NULL);
    latency_ms = elapsed_ms(start, &end);
    record_query_latency(latency_ms);
    add_log(domain, action, transport, source, uid, qtype, result, rule, upstream, latency_ms);
}

static void handle_dns_query(const config_t *cfg, const uint8_t *query, size_t query_len,
                             uint8_t *response, size_t *response_len, const char **action_out,
                             int tcp, const char *source, int uid) {
    char domain[MAX_DOMAIN];
    uint16_t qtype = 0;
    const char *reason = "parse";
    ssize_t forwarded;
    const char *route = "upstream";
    struct timeval start;
    struct timeval upstream_start;
    struct timeval upstream_end;
    int upstream_latency_ms;
    bool cache_negative = false;
    const char *transport = tcp ? "tcp" : "udp";
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
        finish_dns_query("unknown", "invalid", transport, source, uid, qtype,
                "block", "parse", "none", &start);
        return;
    }
    if (evaluate_domain(cfg, domain, uid, &reason) == DECISION_BLOCK) {
        *response_len = build_block_response(query, query_len, response, MAX_PACKET);
        g_stats.blocked++;
        *action_out = reason;
        finish_dns_query(domain, reason, transport, source, uid, qtype,
                "block", reason, "none", &start);
        return;
    }
    *response_len = build_safe_search_response(cfg, domain, qtype, query, query_len,
            response, MAX_PACKET);
    if (*response_len > 0) {
        g_stats.allowed++;
        g_stats.safe_search_rewrites++;
        *action_out = "safe_search";
        finish_dns_query(domain, *action_out, transport, source, uid, qtype,
                "allow", "safe_search", "local", &start);
        return;
    }
    if (cache_lookup(domain, qtype, query, response, response_len, &cache_negative)) {
        g_stats.cache_hits++;
        if (cache_negative) {
            g_stats.cache_negative_hits++;
        } else {
            g_stats.cache_positive_hits++;
        }
        g_stats.allowed++;
        *action_out = cache_negative ? "cache_negative" : "cache";
        finish_dns_query(domain, *action_out, transport, source, uid, qtype,
                "allow", *action_out, "cache", &start);
        return;
    }
    g_stats.cache_misses++;
    g_stats.upstream_requests++;
    gettimeofday(&upstream_start, NULL);
    forwarded = tcp
            ? forward_tcp(cfg, domain, query, query_len, response, MAX_PACKET, &route)
            : forward_udp(cfg, domain, query, query_len, response, MAX_PACKET, &route);
    gettimeofday(&upstream_end, NULL);
    upstream_latency_ms = elapsed_ms(&upstream_start, &upstream_end);
    if (upstream_latency_ms > 0) {
        g_stats.upstream_latency_ms += (uint64_t) upstream_latency_ms;
    }
    if (forwarded > 0) {
        *response_len = (size_t) forwarded;
        if (!dns_response_truncated(response, *response_len)) {
            cache_store(domain, qtype, response, *response_len);
        }
        g_stats.allowed++;
        g_stats.upstream_successes++;
        *action_out = route;
        finish_dns_query(domain, route, transport, source, uid, qtype,
                "allow", "upstream", route, &start);
        return;
    }
    g_stats.upstream_failures++;
    if (cfg->fail_open) {
        *response_len = 0;
        *action_out = "upstream_failed";
        g_stats.fail_open_drops++;
        finish_dns_query(domain, *action_out, transport, source, uid, qtype,
                "fail_open", "upstream_failed", route, &start);
    } else {
        *response_len = build_block_response(query, query_len, response, MAX_PACKET);
        g_stats.blocked++;
        *action_out = "fail_closed";
        g_stats.fail_closed_blocks++;
        finish_dns_query(domain, *action_out, transport, source, uid, qtype,
                "block", "fail_closed", route, &start);
    }
}

static uint16_t sockaddr_port(const struct sockaddr_storage *addr) {
    if (addr == NULL) {
        return 0;
    }
    if (addr->ss_family == AF_INET) {
        return ntohs(((const struct sockaddr_in *) addr)->sin_port);
    }
    if (addr->ss_family == AF_INET6) {
        return ntohs(((const struct sockaddr_in6 *) addr)->sin6_port);
    }
    return 0;
}

static bool lookup_uid_cache(uint16_t port, int family, int tcp, int *uid) {
    int i;
    uint64_t now = now_seconds();
    for (i = 0; i < UID_CACHE_SIZE; i++) {
        uid_cache_entry_t *entry = &g_uid_cache[i];
        if (!entry->used || entry->expires_at < now) {
            continue;
        }
        if (entry->port == port && entry->family == family && entry->tcp == tcp) {
            *uid = entry->uid;
            g_stats.uid_cache_hits++;
            return true;
        }
    }
    return false;
}

static void store_uid_cache(uint16_t port, int family, int tcp, int uid) {
    uid_cache_entry_t *entry = &g_uid_cache[g_uid_cache_pos % UID_CACHE_SIZE];
    g_uid_cache_pos = (g_uid_cache_pos + 1) % UID_CACHE_SIZE;
    entry->port = port;
    entry->family = family;
    entry->tcp = tcp;
    entry->uid = uid;
    entry->expires_at = now_seconds() + UID_CACHE_TTL;
    entry->used = true;
}

static int lookup_uid_in_proc_file(const char *path, uint16_t port) {
    FILE *fp;
    char line[512];
    fp = fopen(path, "r");
    if (fp == NULL) {
        return UID_UNKNOWN;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        char local[96];
        char remote[96];
        char state[8];
        char *colon;
        unsigned int local_port;
        unsigned int uid;
        if (sscanf(line, " %*d: %95s %95s %7s %*s %*s %*s %u",
                local, remote, state, &uid) != 4) {
            continue;
        }
        (void) remote;
        (void) state;
        colon = strchr(local, ':');
        if (colon == NULL) {
            continue;
        }
        if (sscanf(colon + 1, "%x", &local_port) != 1) {
            continue;
        }
        if (local_port == port) {
            fclose(fp);
            return (int) uid;
        }
    }
    fclose(fp);
    return UID_UNKNOWN;
}

static int lookup_query_uid(const struct sockaddr_storage *peer, int tcp) {
    uint16_t port = sockaddr_port(peer);
    int family = peer == NULL ? AF_UNSPEC : peer->ss_family;
    int uid;
    if (port == 0) {
        g_stats.uid_lookup_misses++;
        return UID_UNKNOWN;
    }
    if (lookup_uid_cache(port, family, tcp, &uid)) {
        return uid;
    }
    if (tcp) {
        uid = lookup_uid_in_proc_file("/proc/net/tcp", port);
        if (uid == UID_UNKNOWN) {
            uid = lookup_uid_in_proc_file("/proc/net/tcp6", port);
        }
    } else {
        uid = lookup_uid_in_proc_file("/proc/net/udp", port);
        if (uid == UID_UNKNOWN) {
            uid = lookup_uid_in_proc_file("/proc/net/udp6", port);
        }
    }
    store_uid_cache(port, family, tcp, uid);
    if (uid == UID_UNKNOWN) {
        g_stats.uid_lookup_misses++;
    } else {
        g_stats.uid_lookup_successes++;
    }
    return uid;
}

static void format_sockaddr_endpoint(const struct sockaddr_storage *addr, char *out, size_t out_len) {
    char host[INET6_ADDRSTRLEN];
    uint16_t port;
    if (out == NULL || out_len == 0) {
        return;
    }
    safe_copy(out, out_len, "unknown");
    if (addr == NULL) {
        return;
    }
    if (addr->ss_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *) addr;
        if (inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host)) == NULL) {
            return;
        }
        port = ntohs(in->sin_port);
        snprintf(out, out_len, "%s:%u", host, (unsigned int) port);
    } else if (addr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *) addr;
        if (inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host)) == NULL) {
            return;
        }
        port = ntohs(in6->sin6_port);
        snprintf(out, out_len, "[%s]:%u", host, (unsigned int) port);
    }
}

static bool handle_udp(int fd, int flags) {
    uint8_t query[MAX_PACKET];
    uint8_t response[MAX_PACKET];
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);
    char source[64];
    int uid;
    ssize_t got;
    size_t response_len = 0;
    const char *action = "none";
    struct timeval start;
    struct timeval end;
    got = recvfrom(fd, query, sizeof(query), flags, (struct sockaddr *) &peer, &peer_len);
    if (got <= 0) {
        return false;
    }
    format_sockaddr_endpoint(&peer, source, sizeof(source));
    uid = lookup_query_uid(&peer, 0);
    gettimeofday(&start, NULL);
    handle_dns_query(&g_cfg, query, (size_t) got, response, &response_len, &action, 0, source, uid);
    gettimeofday(&end, NULL);
    (void) action;
    if (response_len > 0) {
        sendto(fd, response, response_len, 0, (struct sockaddr *) &peer, peer_len);
    }
    if (response_len == 0 && !g_cfg.fail_open) {
        add_log("unknown", "no_response", "udp", source, uid, 0,
                "block", "no_response", "none", elapsed_ms(&start, &end));
    }
    return true;
}

static void handle_tcp_client(int client, const char *source, int uid) {
    uint8_t lenbuf[2];
    uint8_t query[MAX_PACKET];
    uint8_t response[MAX_PACKET + 2];
    uint16_t qlen;
    size_t response_len = 0;
    const char *action = "none";
    set_socket_timeout(client, CLIENT_TIMEOUT_MS);
    if (read_full(client, lenbuf, 2) != 2) {
        if (socket_timed_out()) {
            g_stats.tcp_client_timeouts++;
        }
        return;
    }
    qlen = (uint16_t) ((lenbuf[0] << 8) | lenbuf[1]);
    if (qlen == 0 || qlen > MAX_PACKET) {
        return;
    }
    if (read_full(client, query, qlen) != qlen) {
        if (socket_timed_out()) {
            g_stats.tcp_client_timeouts++;
        }
        return;
    }
    handle_dns_query(&g_cfg, query, qlen, response + 2, &response_len, &action, 1, source, uid);
    (void) action;
    if (response_len > 0) {
        response[0] = (uint8_t) ((response_len >> 8) & 0xffu);
        response[1] = (uint8_t) (response_len & 0xffu);
        send(client, response, response_len + 2, 0);
    }
}

static void handle_tcp(int fd) {
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);
    char source[64];
    int uid;
    int client = accept(fd, (struct sockaddr *) &peer, &peer_len);
    if (client >= 0) {
        format_sockaddr_endpoint(&peer, source, sizeof(source));
        uid = lookup_query_uid(&peer, 1);
        handle_tcp_client(client, source, uid);
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
    long memory_rss_kb = read_proc_status_kb("VmRSS");
    long memory_hwm_kb = read_proc_status_kb("VmHWM");
    uint64_t cpu_user_ticks;
    uint64_t cpu_system_ticks;
    uint64_t cpu_user_ms;
    uint64_t cpu_system_ms;
    uint64_t cpu_total_ms;
    uint64_t log_ring_entries;
    uint64_t log_unflushed_entries;

    read_proc_cpu_ticks(&cpu_user_ticks, &cpu_system_ticks);
    cpu_user_ms = cpu_ticks_to_ms(cpu_user_ticks);
    cpu_system_ms = cpu_ticks_to_ms(cpu_system_ticks);
    cpu_total_ms = cpu_user_ms + cpu_system_ms;
    read_log_stats(&log_ring_entries, &log_unflushed_entries);
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
            "generation=%llu\nupstreams=%d\nsplit_upstreams=%d\nupstream_probe=%s\n"
            "compiled_upstream_addresses=%d\nreusable_udp_upstream_sockets=%d\n"
            "resolver_scope_hash=%llu\n"
            "upstream_probe_ms=%d\nupstream_probe_index=%d\nupstream_probe_rcode=%d\n"
            "queries=%llu\nblocked=%llu\nallowed=%llu\ncache_size=%d\ncache_entries=%d\n"
            "socket_buffer_bytes=%d\nudp_drain_limit=%d\n"
            "udp_drain_batches=%llu\nudp_drain_packets=%llu\n"
            "cache_positive_entries=%d\ncache_negative_entries=%d\n"
            "cache_positive_hits=%llu\ncache_negative_hits=%llu\n"
            "cache_positive_stores=%llu\ncache_negative_stores=%llu\n"
            "cache_ttl_rewrites=%llu\ncache_lru_evictions=%llu\n"
            "cache_reload_preserved=%llu\ncache_reload_dropped=%llu\n"
            "cache_reload_scope_changes=%llu\n"
            "upstream_tcp_fallbacks=%llu\nupstream_truncated_responses=%llu\n"
            "upstream_udp_socket_reuses=%llu\nupstream_udp_stale_replies=%llu\n"
            "tcp_client_timeouts=%llu\ncontrol_client_timeouts=%llu\n"
            "uid_lookup_successes=%llu\nuid_lookup_misses=%llu\nuid_cache_hits=%llu\n"
            "memory_rss_kb=%ld\nmemory_hwm_kb=%ld\ncpu_user_ms=%llu\n"
            "cpu_system_ms=%llu\ncpu_total_ms=%llu\n"
            "query_logging=%d\npersist_query_logs=%d\n"
            "safe_search=%d\nsafe_search_rewrites=%llu\n"
            "log_writer_thread=%d\nlog_ring_entries=%llu\nlog_unflushed_entries=%llu\n"
            "exact_allow_index_size=%d\nexact_block_index_size=%d\n"
            "app_exact_allow_index_size=%d\napp_exact_block_index_size=%d\n"
            "suffix_allow_trie_nodes=%d\nsuffix_block_trie_nodes=%d\n"
            "app_suffix_allow_trie_nodes=%d\napp_suffix_block_trie_nodes=%d\n"
            "rules_app_exact_allow=%d\nrules_app_exact_block=%d\n"
            "rules_app_suffix_allow=%d\nrules_app_suffix_block=%d\n"
            "rules_total=%d\n",
            (long) getpid(),
            (unsigned long long) (now_seconds() - g_stats.start_time),
            g_cfg.listen_port,
            (unsigned long long) g_cfg.generation,
            g_cfg.upstream_count,
            g_cfg.split_upstream_count,
            response_len > 0 ? "ok" : "fail",
            compiled_upstream_address_count(&g_cfg),
            reusable_udp_upstream_socket_count(&g_cfg),
            (unsigned long long) g_cfg.resolver_scope_hash,
            latency_ms,
            upstream_index,
            rcode,
            (unsigned long long) g_stats.queries,
            (unsigned long long) g_stats.blocked,
            (unsigned long long) g_stats.allowed,
            g_cfg.cache_size,
            cache_entry_count(),
            DNS_SOCKET_BUFFER_BYTES,
            UDP_DRAIN_LIMIT,
            (unsigned long long) g_stats.udp_drain_batches,
            (unsigned long long) g_stats.udp_drain_packets,
            cache_entry_count_by_type(false),
            cache_entry_count_by_type(true),
            (unsigned long long) g_stats.cache_positive_hits,
            (unsigned long long) g_stats.cache_negative_hits,
            (unsigned long long) g_stats.cache_positive_stores,
            (unsigned long long) g_stats.cache_negative_stores,
            (unsigned long long) g_stats.cache_ttl_rewrites,
            (unsigned long long) g_stats.cache_lru_evictions,
            (unsigned long long) g_stats.cache_reload_preserved,
            (unsigned long long) g_stats.cache_reload_dropped,
            (unsigned long long) g_stats.cache_reload_scope_changes,
            (unsigned long long) g_stats.upstream_tcp_fallbacks,
            (unsigned long long) g_stats.upstream_truncated_responses,
            (unsigned long long) g_stats.upstream_udp_socket_reuses,
            (unsigned long long) g_stats.upstream_udp_stale_replies,
            (unsigned long long) g_stats.tcp_client_timeouts,
            (unsigned long long) g_stats.control_client_timeouts,
            (unsigned long long) g_stats.uid_lookup_successes,
            (unsigned long long) g_stats.uid_lookup_misses,
            (unsigned long long) g_stats.uid_cache_hits,
            memory_rss_kb,
            memory_hwm_kb,
            (unsigned long long) cpu_user_ms,
            (unsigned long long) cpu_system_ms,
            (unsigned long long) cpu_total_ms,
            g_cfg.query_logging,
            g_cfg.persist_query_logs,
            g_cfg.safe_search,
            (unsigned long long) g_stats.safe_search_rewrites,
            g_log_thread_started ? 1 : 0,
            (unsigned long long) log_ring_entries,
            (unsigned long long) log_unflushed_entries,
            g_cfg.exact_allow_index_size,
            g_cfg.exact_block_index_size,
            g_cfg.app_exact_allow_index_size,
            g_cfg.app_exact_block_index_size,
            g_cfg.suffix_allow_trie.count,
            g_cfg.suffix_block_trie.count,
            g_cfg.app_suffix_allow_trie.count,
            g_cfg.app_suffix_block_trie.count,
            g_cfg.app_exact_allow.count,
            g_cfg.app_exact_block.count,
            g_cfg.app_suffix_allow.count,
            g_cfg.app_suffix_block.count,
            g_cfg.exact_allow.count + g_cfg.suffix_allow.count
                    + g_cfg.exact_block.count + g_cfg.suffix_block.count
                    + g_cfg.regex_allow.count + g_cfg.regex_block.count
                    + g_cfg.temp_allow_count + g_cfg.temp_block_count
                    + g_cfg.app_exact_allow.count + g_cfg.app_exact_block.count
                    + g_cfg.app_suffix_allow.count + g_cfg.app_suffix_block.count);
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
                "upstream[%d]=%s:%d protocol=%s status=%s latency_ms=%d rcode=%d bytes=%ld\n",
                i,
                g_cfg.upstreams[i].host,
                g_cfg.upstreams[i].port,
                upstream_protocol_name(g_cfg.upstreams[i].protocol),
                response_len > 0 ? "ok" : "fail",
                latency_ms,
                rcode,
                (long) response_len);
    }
}

static void write_history_response(int client, const char *filter) {
    FILE *fp;
    char line[LOG_LINE_MAX];
    char log_file[sizeof(g_log_file_path)];
    char (*matches)[LOG_LINE_MAX];
    int count = 0;
    int pos = 0;
    int i;

    flush_logs();
    if (!copy_log_file_path(log_file, sizeof(log_file))) {
        return;
    }
    fp = fopen(log_file, "r");
    if (fp == NULL) {
        return;
    }
    matches = (char (*)[LOG_LINE_MAX]) calloc(LOG_HISTORY_LIMIT, LOG_LINE_MAX);
    if (matches == NULL) {
        fclose(fp);
        return;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        trim(line);
        if (line[0] == '\0' || !ascii_contains_ci(line, filter)) {
            continue;
        }
        safe_copy(matches[pos], LOG_LINE_MAX, line);
        pos = (pos + 1) % LOG_HISTORY_LIMIT;
        if (count < LOG_HISTORY_LIMIT) {
            count++;
        }
    }
    fclose(fp);

    for (i = 0; i < count; i++) {
        int idx = (pos - count + i + LOG_HISTORY_LIMIT) % LOG_HISTORY_LIMIT;
        write_control_response(client, "%s\n", matches[idx]);
    }
    free(matches);
}

static void handle_control(int fd) {
    int client = accept(fd, NULL, NULL);
    char cmd[128];
    ssize_t n;
    if (client < 0) {
        return;
    }
    set_socket_timeout(client, CLIENT_TIMEOUT_MS);
    n = recv(client, cmd, sizeof(cmd) - 1, 0);
    if (n <= 0) {
        if (socket_timed_out()) {
            g_stats.control_client_timeouts++;
        }
        close(client);
        return;
    }
    cmd[n] = '\0';
    trim(cmd);
    if (strcmp(cmd, "status") == 0 || strcmp(cmd, "stats") == 0) {
        long memory_rss_kb = read_proc_status_kb("VmRSS");
        long memory_hwm_kb = read_proc_status_kb("VmHWM");
        uint64_t cpu_user_ticks;
        uint64_t cpu_system_ticks;
        uint64_t cpu_user_ms;
        uint64_t cpu_system_ms;
        uint64_t cpu_total_ms;
        uint64_t log_ring_entries;
        uint64_t log_unflushed_entries;

        read_proc_cpu_ticks(&cpu_user_ticks, &cpu_system_ticks);
        cpu_user_ms = cpu_ticks_to_ms(cpu_user_ticks);
        cpu_system_ms = cpu_ticks_to_ms(cpu_system_ticks);
        cpu_total_ms = cpu_user_ms + cpu_system_ms;
        read_log_stats(&log_ring_entries, &log_unflushed_entries);
        write_control_response(client,
                "running=1\npid=%ld\nuptime=%llu\ngeneration=%llu\n"
                "queries=%llu\nudp_queries=%llu\ntcp_queries=%llu\ninvalid_queries=%llu\n"
                "udp_drain_batches=%llu\nudp_drain_packets=%llu\n"
                "tcp_client_timeouts=%llu\ncontrol_client_timeouts=%llu\n"
                "allowed=%llu\nblocked=%llu\nfail_open_drops=%llu\nfail_closed_blocks=%llu\n"
                "memory_rss_kb=%ld\nmemory_hwm_kb=%ld\ncpu_user_ms=%llu\n"
                "cpu_system_ms=%llu\ncpu_total_ms=%llu\n"
                "query_logging=%d\npersist_query_logs=%d\n"
                "safe_search=%d\nsafe_search_rewrites=%llu\n"
                "log_writer_thread=%d\nlog_ring_entries=%llu\nlog_unflushed_entries=%llu\n"
                "socket_buffer_bytes=%d\nudp_drain_limit=%d\n"
                "cache_size=%d\ncache_entries=%d\ncache_hits=%llu\ncache_misses=%llu\n"
                "cache_positive_entries=%d\ncache_negative_entries=%d\n"
                "cache_positive_hits=%llu\ncache_negative_hits=%llu\n"
                "cache_hit_rate_ppm=%llu\ncache_stores=%llu\n"
                "cache_positive_stores=%llu\ncache_negative_stores=%llu\n"
                "cache_expired=%llu\ncache_evictions=%llu\ncache_ttl_rewrites=%llu\n"
                "cache_lru_evictions=%llu\n"
                "cache_reload_preserved=%llu\ncache_reload_dropped=%llu\n"
                "cache_reload_scope_changes=%llu\n"
                "upstream_requests=%llu\nupstream_successes=%llu\nupstream_failures=%llu\n"
                "upstream_tcp_fallbacks=%llu\nupstream_truncated_responses=%llu\n"
                "upstream_udp_socket_reuses=%llu\nupstream_udp_stale_replies=%llu\n"
                "uid_lookup_successes=%llu\nuid_lookup_misses=%llu\nuid_cache_hits=%llu\n"
                "compiled_upstream_addresses=%d\nreusable_udp_upstream_sockets=%d\n"
                "resolver_scope_hash=%llu\n"
                "avg_latency_ms=%llu\nmax_latency_ms=%llu\nupstream_avg_latency_ms=%llu\n"
                "reloads=%llu\nexact_allow_index_size=%d\nexact_block_index_size=%d\n"
                "app_exact_allow_index_size=%d\napp_exact_block_index_size=%d\n"
                "suffix_allow_trie_nodes=%d\n"
                "suffix_block_trie_nodes=%d\napp_suffix_allow_trie_nodes=%d\n"
                "app_suffix_block_trie_nodes=%d\nrules_exact_allow=%d\nrules_suffix_allow=%d\n"
                "rules_exact_block=%d\nrules_suffix_block=%d\n"
                "rules_app_exact_allow=%d\nrules_app_exact_block=%d\n"
                "rules_app_suffix_allow=%d\nrules_app_suffix_block=%d\n"
                "rules_regex_allow=%d\nrules_regex_block=%d\n"
                "rules_temp_allow=%d\nrules_temp_block=%d\nsplit_upstreams=%d\n",
                (long) getpid(),
                (unsigned long long) (now_seconds() - g_stats.start_time),
                (unsigned long long) g_cfg.generation,
                (unsigned long long) g_stats.queries,
                (unsigned long long) g_stats.udp_queries,
                (unsigned long long) g_stats.tcp_queries,
                (unsigned long long) g_stats.invalid_queries,
                (unsigned long long) g_stats.udp_drain_batches,
                (unsigned long long) g_stats.udp_drain_packets,
                (unsigned long long) g_stats.tcp_client_timeouts,
                (unsigned long long) g_stats.control_client_timeouts,
                (unsigned long long) g_stats.allowed,
                (unsigned long long) g_stats.blocked,
                (unsigned long long) g_stats.fail_open_drops,
                (unsigned long long) g_stats.fail_closed_blocks,
                memory_rss_kb,
                memory_hwm_kb,
                (unsigned long long) cpu_user_ms,
                (unsigned long long) cpu_system_ms,
                (unsigned long long) cpu_total_ms,
                g_cfg.query_logging,
                g_cfg.persist_query_logs,
                g_cfg.safe_search,
                (unsigned long long) g_stats.safe_search_rewrites,
                g_log_thread_started ? 1 : 0,
                (unsigned long long) log_ring_entries,
                (unsigned long long) log_unflushed_entries,
                DNS_SOCKET_BUFFER_BYTES,
                UDP_DRAIN_LIMIT,
                g_cfg.cache_size,
                cache_entry_count(),
                (unsigned long long) g_stats.cache_hits,
                (unsigned long long) g_stats.cache_misses,
                cache_entry_count_by_type(false),
                cache_entry_count_by_type(true),
                (unsigned long long) g_stats.cache_positive_hits,
                (unsigned long long) g_stats.cache_negative_hits,
                (unsigned long long) div_u64(g_stats.cache_hits * 1000000ULL,
                        g_stats.cache_hits + g_stats.cache_misses),
                (unsigned long long) g_stats.cache_stores,
                (unsigned long long) g_stats.cache_positive_stores,
                (unsigned long long) g_stats.cache_negative_stores,
                (unsigned long long) g_stats.cache_expired,
                (unsigned long long) g_stats.cache_evictions,
                (unsigned long long) g_stats.cache_ttl_rewrites,
                (unsigned long long) g_stats.cache_lru_evictions,
                (unsigned long long) g_stats.cache_reload_preserved,
                (unsigned long long) g_stats.cache_reload_dropped,
                (unsigned long long) g_stats.cache_reload_scope_changes,
                (unsigned long long) g_stats.upstream_requests,
                (unsigned long long) g_stats.upstream_successes,
                (unsigned long long) g_stats.upstream_failures,
                (unsigned long long) g_stats.upstream_tcp_fallbacks,
                (unsigned long long) g_stats.upstream_truncated_responses,
                (unsigned long long) g_stats.upstream_udp_socket_reuses,
                (unsigned long long) g_stats.upstream_udp_stale_replies,
                (unsigned long long) g_stats.uid_lookup_successes,
                (unsigned long long) g_stats.uid_lookup_misses,
                (unsigned long long) g_stats.uid_cache_hits,
                compiled_upstream_address_count(&g_cfg),
                reusable_udp_upstream_socket_count(&g_cfg),
                (unsigned long long) g_cfg.resolver_scope_hash,
                (unsigned long long) div_u64(g_stats.total_latency_ms, g_stats.queries),
                (unsigned long long) g_stats.max_latency_ms,
                (unsigned long long) div_u64(g_stats.upstream_latency_ms, g_stats.upstream_requests),
                (unsigned long long) g_stats.reloads,
                g_cfg.exact_allow_index_size,
                g_cfg.exact_block_index_size,
                g_cfg.app_exact_allow_index_size,
                g_cfg.app_exact_block_index_size,
                g_cfg.suffix_allow_trie.count,
                g_cfg.suffix_block_trie.count,
                g_cfg.app_suffix_allow_trie.count,
                g_cfg.app_suffix_block_trie.count,
                g_cfg.exact_allow.count,
                g_cfg.suffix_allow.count,
                g_cfg.exact_block.count,
                g_cfg.suffix_block.count,
                g_cfg.app_exact_allow.count,
                g_cfg.app_exact_block.count,
                g_cfg.app_suffix_allow.count,
                g_cfg.app_suffix_block.count,
                g_cfg.regex_allow.count,
                g_cfg.regex_block.count,
                g_cfg.temp_allow_count,
                g_cfg.temp_block_count,
                g_cfg.split_upstream_count);
    } else if (strcmp(cmd, "health") == 0) {
        write_health_response(client);
    } else if (strcmp(cmd, "benchmark") == 0) {
        write_benchmark_response(client);
    } else if (strcmp(cmd, "validate") == 0) {
        write_validate_response(client);
    } else if (strcmp(cmd, "reload") == 0) {
        if (reload_config()) {
            write_control_response(client, "ok reload generation=%llu\n", (unsigned long long) g_cfg.generation);
        } else {
            write_control_response(client, "error reload\n");
        }
    } else if (strcmp(cmd, "logs") == 0) {
        int i;
        int count = 0;
        log_entry_t entries[LOG_RING];
        pthread_mutex_lock(&g_log_mutex);
        for (i = 0; i < LOG_RING; i++) {
            int idx = (g_log_pos + i) % LOG_RING;
            if (g_logs[idx].timestamp == 0) {
                continue;
            }
            entries[count++] = g_logs[idx];
        }
        pthread_mutex_unlock(&g_log_mutex);
        for (i = 0; i < count; i++) {
            write_control_response(client,
                    "%llu %s %s %dms transport=%s source=%s uid=%d qtype=%u result=%s rule=%s upstream=%s\n",
                    (unsigned long long) entries[i].timestamp,
                    entries[i].action,
                    entries[i].domain,
                    entries[i].latency_ms,
                    entries[i].transport,
                    entries[i].source,
                    entries[i].uid,
                    (unsigned int) entries[i].qtype,
                    entries[i].result,
                    entries[i].rule,
                    entries[i].upstream);
        }
    } else if (strcmp(cmd, "history") == 0) {
        write_history_response(client, "");
    } else if (strncmp(cmd, "history ", 8) == 0) {
        char *filter = cmd + 8;
        trim(filter);
        write_history_response(client, filter);
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
        g_reload_requested = 1;
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
    uint64_t last_heartbeat = 0;
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
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);
    udp_fd = create_udp_socket(g_cfg.listen_port);
    tcp_fd = create_tcp_socket(g_cfg.listen_port);
    control_fd = create_control_socket(g_cfg.control_socket);
    if (udp_fd < 0 || tcp_fd < 0 || control_fd < 0) {
        if (udp_fd >= 0) {
            close(udp_fd);
        }
        if (tcp_fd >= 0) {
            close(tcp_fd);
        }
        if (control_fd >= 0) {
            close(control_fd);
            unlink(g_cfg.control_socket);
        }
        unlink(g_cfg.pid_file);
        if (g_cfg.heartbeat_file[0] != '\0') {
            unlink(g_cfg.heartbeat_file);
        }
        fprintf(stderr, "failed to create listeners on port %d\n", g_cfg.listen_port);
        return 1;
    }
    /* Publish the PID only after listeners exist so supervisors do not accept a half-start. */
    write_pid_file();
    write_heartbeat_file();
    last_heartbeat = now_seconds();
    start_log_thread();
    while (g_running) {
        fd_set readfds;
        struct timeval timeout;
        uint64_t heartbeat_now;
        int maxfd = udp_fd;
        int ready;
        if (g_reload_requested) {
            g_reload_requested = 0;
            reload_config();
        }
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
            int drained = 0;
            int limit = AFWALL_HAS_MSG_DONTWAIT ? UDP_DRAIN_LIMIT : 1;
            /* Drain a bounded UDP burst so queued DNS packets are not left behind under load. */
            while (drained < limit && handle_udp(udp_fd, MSG_DONTWAIT)) {
                drained++;
            }
            if (drained > 1) {
                g_stats.udp_drain_batches++;
                g_stats.udp_drain_packets += (uint64_t) drained;
            }
        }
        if (FD_ISSET(tcp_fd, &readfds)) {
            handle_tcp(tcp_fd);
        }
        if (FD_ISSET(control_fd, &readfds)) {
            handle_control(control_fd);
        }
        if (!g_log_thread_started) {
            flush_logs();
        }
        heartbeat_now = now_seconds();
        if (heartbeat_now != last_heartbeat) {
            write_heartbeat_file();
            last_heartbeat = heartbeat_now;
        }
    }
    stop_log_thread();
    close(udp_fd);
    close(tcp_fd);
    close(control_fd);
    unlink(g_cfg.control_socket);
    unlink(g_cfg.pid_file);
    if (g_cfg.heartbeat_file[0] != '\0') {
        unlink(g_cfg.heartbeat_file);
    }
    free_config_dynamic(&g_cfg);
    return 0;
}
