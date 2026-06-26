package dev.ukanth.ufirewall.dns;

import android.content.Context;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Build;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import dev.ukanth.ufirewall.Api;
import dev.ukanth.ufirewall.R;
import dev.ukanth.ufirewall.service.RootCommand;
import dev.ukanth.ufirewall.util.ApplicationErrorLog;
import dev.ukanth.ufirewall.util.G;

public final class DnsHijackManager {

    private static final String TAG = "AFWallDnsHijack";
    private static final String DAEMON_NAME = "afwall_dnsd";
    private static final String WORK_DIR = "dnsd";
    private static final String ENABLED_MARKER = "afwall_dnsd.enabled";
    private static final String SUPERVISOR = "afwall_dnsd_supervisor.sh";
    private static final String CONF = "afwall_dnsd.conf";
    private static final String PID = "afwall_dnsd.pid";
    private static final String SOCKET = "afwall_dnsd.sock";
    private static final String QUERY_LOG = "afwall_dnsd.log";
    private static final String SUPERVISOR_LOG = "afwall_dnsd_supervisor.log";
    private static final String SUPERVISOR_PID = "afwall_dnsd_supervisor.pid";
    private static final String RESTART_COUNT = "afwall_dnsd_restart_count";
    private static final String LAST_EXIT = "afwall_dnsd_last_exit";
    private static final String BOOT_SCRIPT = "afwall_dnsd_boot.sh";
    private static final String BOOT_LOG = "afwall_dnsd_boot.log";
    private static final String CHAIN_V4 = "afwall-dns";
    private static final String CHAIN_V4_PRE = "afwall-dns-pre";
    private static final String CHAIN_V6 = "afwall-dns6";
    private static final String CHAIN_V6_PRE = "afwall-dns6-pre";
    private static final int DEFAULT_PORT = 5354;
    public static final int RULE_ALLOW_EXACT = 1;
    public static final int RULE_ALLOW_SUFFIX = 2;
    public static final int RULE_BLOCK_EXACT = 3;
    public static final int RULE_BLOCK_SUFFIX = 4;
    public static final int RULE_TEMP_ALLOW = 5;
    public static final int RULE_TEMP_BLOCK = 6;
    private static final long TEMP_RULE_DURATION_SECONDS = 15L * 60L;

    private DnsHijackManager() {
    }

    public static void appendApplyCommands(Context context, List<String> commands, boolean ipv6) {
        appendPurgeRules(commands, ipv6);
        if (!G.enableDnsHijack()) {
            if (!ipv6) {
                appendStopCommand(context, commands);
                appendRemoveBootPersistenceCommand(commands);
            }
            return;
        }

        // Do not queue NAT redirects unless the daemon and supervisor are ready; otherwise DNS
        // capture would turn a preparation failure into device-wide DNS loss.
        if (!prepareDaemon(context)) {
            ApplicationErrorLog.add(context, "DNS hijacker was enabled but daemon files could not be prepared; redirect rules were not queued");
            return;
        }

        if (!ipv6) {
            ApplicationErrorLog.add(context, "DNS hijacker enabled; daemon start and DNS redirect rules queued");
            logRedirectPolicy(context, "DNS redirect policy queued");
            commands.add("#LITERAL# " + shellQuote(supervisorPath(context)) + " start");
            appendBootPersistenceCommand(context, commands);
        }
        appendRedirectRules(commands, ipv6);
    }

    public static void appendPurgeCommands(Context context, List<String> commands, boolean ipv6) {
        appendPurgeRules(commands, ipv6);
        if (!ipv6) {
            appendStopCommand(context, commands);
            appendRemoveBootPersistenceCommand(commands);
        }
    }

    public static void requestReload(Context context) {
        runSupervisorAction(context, "reload", null);
    }

    public static void runSupervisorAction(Context context, String action, RootCommand.Callback callback) {
        if (context == null) {
            return;
        }
        String safeAction = normalizeSupervisorAction(action);
        if (safeAction == null) {
            failSupervisorAction(context, callback, "DNS hijacker supervisor action was invalid: " + action);
            return;
        }
        if (!"stop".equals(safeAction) && !prepareDaemon(context)) {
            failSupervisorAction(context, callback, "DNS hijacker " + safeAction + " requested but daemon files could not be prepared");
            return;
        }
        File supervisor = new File(workDir(context), SUPERVISOR);
        if (!supervisor.exists()) {
            failSupervisorAction(context, callback, "DNS hijacker " + safeAction + " requested but supervisor script is missing");
            return;
        }
        List<String> commands = new ArrayList<>();
        commands.add(shellQuote(supervisor.getAbsolutePath()) + " " + safeAction);
        ApplicationErrorLog.add(context, "DNS hijacker supervisor action queued: " + safeAction);
        new RootCommand()
                .setLogging(true)
                .setReopenShell(true)
                .setFailureToast(R.string.error_apply)
                .setCallback(callback)
                .run(context.getApplicationContext(), commands);
    }

    public static void repairDnsProtection(Context context, RootCommand.Callback callback) {
        if (context == null) {
            return;
        }
        if (!G.enableDnsHijack()) {
            failSupervisorAction(context, callback, "DNS hijacker repair requested while DNS capture is disabled");
            return;
        }
        if (!prepareDaemon(context)) {
            failSupervisorAction(context, callback, "DNS hijacker repair requested but daemon files could not be prepared");
            return;
        }

        List<String> commands = buildRootRepairCommands(context);
        ApplicationErrorLog.add(context, "DNS hijacker repair queued: daemon start and DNS redirect reinstall");
        new RootCommand()
                .setLogging(true)
                .setReopenShell(true)
                .setFailureToast(R.string.error_apply)
                .setCallback(callback)
                .run(context.getApplicationContext(), commands);
    }

    public static String collectLocalDiagnostics(Context context) {
        StringBuilder out = new StringBuilder();
        File dir = workDir(context);
        File daemon = new File(dir, DAEMON_NAME);
        File supervisor = new File(dir, SUPERVISOR);
        File config = new File(dir, CONF);
        File pid = new File(dir, PID);
        File socket = new File(dir, SOCKET);
        File queryLog = new File(dir, QUERY_LOG);
        File supervisorLog = new File(dir, SUPERVISOR_LOG);
        File supervisorPid = new File(dir, SUPERVISOR_PID);
        File restartCount = new File(dir, RESTART_COUNT);
        File lastExit = new File(dir, LAST_EXIT);
        File bootScript = new File(dir, BOOT_SCRIPT);
        File bootLog = new File(dir, BOOT_LOG);

        out.append("enabled_pref=").append(G.enableDnsHijack()).append('\n');
        out.append("active_profile=").append(G.activeDnsHijackPolicyProfile()).append('\n');
        out.append("profile_dns_overrides_enabled=").append(G.dnsHijackUseProfilePolicy()).append('\n');
        out.append("active_profile_dns_override_saved=")
                .append(G.activeDnsHijackProfilePolicySaved()).append('\n');
        out.append("blocklist_storage=").append(G.dnsHijackBlocklistDirectoryName("dnsd_blocklists"))
                .append('\n');
        out.append("boot_persistence_pref=").append(G.dnsHijackBootPersistence()).append('\n');
        out.append("port=").append(G.dnsHijackPort(DEFAULT_PORT)).append('\n');
        out.append("fail_open=").append(G.dnsHijackFailOpen()).append('\n');
        out.append("strict_mode=").append(G.dnsHijackStrictMode()).append('\n');
        out.append("timeout_ms=").append(G.dnsHijackTimeoutMs()).append('\n');
        out.append("cache_size=").append(G.dnsHijackCacheSize()).append('\n');
        out.append("split_upstream_entries=").append(countLines(G.dnsHijackSplitUpstreams())).append('\n');
        out.append("capture_uid_entries=").append(parseUidList(G.dnsHijackCaptureUids()).size()).append('\n');
        out.append("bypass_uid_entries=").append(parseUidList(G.dnsHijackBypassUids()).size()).append('\n');
        out.append("capture_interface_entries=")
                .append(parseInterfaceList(G.dnsHijackCaptureInterfaces()).size()).append('\n');
        out.append("bypass_interface_entries=")
                .append(parseInterfaceList(G.dnsHijackBypassInterfaces()).size()).append('\n');
        out.append("scheduled_blocklist_updates=").append(G.dnsHijackScheduledBlocklistUpdates()).append('\n');
        out.append("blocklist_update_interval_hours=")
                .append(G.dnsHijackBlocklistUpdateIntervalHours()).append('\n');
        out.append("temporary_allow_entries=").append(countLines(G.dnsHijackTempAllow())).append('\n');
        out.append("temporary_block_entries=").append(countLines(G.dnsHijackTempBlock())).append('\n');
        out.append("\n[blocklists]\n");
        out.append(DnsBlocklistManager.getSummary(context)).append('\n');
        appendFileInfo(out, "work_dir", dir);
        appendFileInfo(out, "daemon", daemon);
        appendFileInfo(out, "supervisor", supervisor);
        appendFileInfo(out, "config", config);
        appendFileInfo(out, "pid", pid);
        appendFileInfo(out, "control_socket", socket);
        appendFileInfo(out, "query_log", queryLog);
        appendFileInfo(out, "supervisor_log", supervisorLog);
        appendFileInfo(out, "supervisor_pid", supervisorPid);
        appendFileInfo(out, "restart_count", restartCount);
        appendFileInfo(out, "last_exit", lastExit);
        appendFileInfo(out, "boot_script", bootScript);
        appendFileInfo(out, "boot_log", bootLog);

        out.append("\n[supervisor metadata]\n");
        appendSmallFileValue(out, "watchdog_pid", supervisorPid);
        appendSmallFileValue(out, "restart_count", restartCount);
        appendSmallFileValue(out, "last_exit", lastExit);

        out.append("\n[control status]\n");
        out.append(queryControl(context, "status"));
        out.append("\n[control health]\n");
        out.append(queryControl(context, "health"));
        out.append("\n[recent queries]\n");
        String logs = queryControl(context, "logs");
        out.append(logs.trim().isEmpty() ? "no daemon query logs reported\n" : logs);
        return out.toString();
    }

    public static List<QueryEntry> getRecentQueries(Context context) {
        return parseQueryEntries(queryControl(context, "logs"));
    }

    public static DnsDashboardSnapshot getDashboardSnapshot(Context context) {
        String status = queryControl(context, "status");
        String health = queryControl(context, "health");
        Map<String, String> statusValues = parseKeyValueLines(status);
        Map<String, String> healthValues = parseKeyValueLines(health);
        Map<String, String> blocklistValues = parseKeyValueLines(DnsBlocklistManager.getSummary(context));

        boolean enabled = G.enableDnsHijack();
        boolean running = "1".equals(firstValue(statusValues, healthValues, "running"))
                || status.contains("running=1") || health.contains("running=1");
        long queries = parseLong(firstValue(statusValues, healthValues, "queries"), 0L);
        long blocked = parseLong(firstValue(statusValues, healthValues, "blocked"), 0L);
        long upstreamLatency = parseLong(firstValue(healthValues, statusValues, "upstream_probe_ms"), -1L);
        String upstreamProbe = firstValue(healthValues, statusValues, "upstream_probe");
        String profile = G.activeDnsHijackPolicyProfile();
        if (profile == null || profile.trim().isEmpty()) {
            profile = "global";
        }
        String blockPercent = queries <= 0L
                ? "0%"
                : String.format(Locale.US, "%.1f%%", (blocked * 100.0d) / queries);
        String protection;
        if (!enabled) {
            protection = "DNS protection disabled";
        } else if (running) {
            protection = "DNS protection active";
        } else {
            protection = "DNS protection enabled, daemon unavailable";
        }

        String statusLine = protection + " | " + queries + " queries | " + blockPercent + " blocked";
        String blocklistUpdated = blocklistValues.containsKey("updated")
                ? blocklistValues.get("updated")
                : "never";
        String upstream = upstreamProbe == null || upstreamProbe.trim().isEmpty()
                ? "unknown"
                : upstreamProbe;
        if (upstreamLatency >= 0L) {
            upstream += " " + upstreamLatency + "ms";
        }
        String details = "Daemon: " + (running ? "running" : "stopped")
                + " | Redirect setting: " + (enabled ? "enabled" : "disabled")
                + " | Profile: " + profile
                + (G.dnsHijackUseProfilePolicy() ? " override" : " global")
                + "\nUpstream: " + upstream
                + " | Blocklist updated: " + blocklistUpdated;
        return new DnsDashboardSnapshot(statusLine, details);
    }

    public static List<QueryEntry> getHistoricalQueries(Context context, String filter) {
        String cleanFilter = sanitizeHistoryFilter(filter);
        String command = cleanFilter.isEmpty() ? "history" : "history " + cleanFilter;
        return parseQueryEntries(queryControl(context, command));
    }

    public static String benchmarkUpstreams(Context context) {
        String daemonResult = queryControl(context, "benchmark");
        if (daemonResult.startsWith("benchmark=1")) {
            ApplicationErrorLog.add(context, "DNS upstream benchmark completed through daemon control socket");
            return daemonResult;
        }

        ApplicationErrorLog.add(context, "DNS upstream benchmark falling back to app UDP probes: "
                + daemonResult.trim());
        return benchmarkUpstreamsDirect();
    }

    public static boolean addRuleFromQuery(Context context, QueryEntry entry, int action) {
        if (entry == null || !entry.hasDomain()) {
            return false;
        }
        String domain = entry.domain;
        boolean added;
        switch (action) {
            case RULE_ALLOW_EXACT:
                added = G.appendDnsHijackAllowExact(domain);
                break;
            case RULE_ALLOW_SUFFIX:
                added = G.appendDnsHijackAllowSuffix(domain);
                break;
            case RULE_BLOCK_EXACT:
                added = G.appendDnsHijackBlockExact(domain);
                break;
            case RULE_BLOCK_SUFFIX:
                added = G.appendDnsHijackBlockSuffix(domain);
                break;
            case RULE_TEMP_ALLOW:
                added = G.appendDnsHijackTempAllow(domain, temporaryRuleExpiresAt());
                break;
            case RULE_TEMP_BLOCK:
                added = G.appendDnsHijackTempBlock(domain, temporaryRuleExpiresAt());
                break;
            default:
                return false;
        }
        if (added) {
            ApplicationErrorLog.add(context, "DNS query action added rule for " + domain + " action=" + action);
            requestReload(context);
        }
        return added;
    }

    public static List<String> buildRootDiagnosticsCommands(Context context) {
        List<String> commands = new ArrayList<>();
        String supervisor = shellQuote(supervisorPath(context));
        String iptables = shellQuote(Api.getBinaryPath(context, false));
        String ip6tables = shellQuote(Api.getBinaryPath(context, true));

        commands.add("echo '[supervisor status]'");
        commands.add("if [ -x " + supervisor + " ]; then " + supervisor + " status 2>&1; else echo 'supervisor missing'; fi");
        commands.add("echo '[pid]'");
        commands.add("cat " + shellQuote(new File(workDir(context), PID).getAbsolutePath()) + " 2>&1 || true");
        commands.add("echo '[IPv4 DNS NAT OUTPUT]'");
        commands.add(iptables + " -t nat -S OUTPUT 2>&1 | grep 'afwall-dns' || true");
        commands.add("echo '[IPv4 DNS NAT chains]'");
        commands.add(iptables + " -t nat -S " + CHAIN_V4 + " 2>&1 || true");
        commands.add(iptables + " -t nat -S " + CHAIN_V4_PRE + " 2>&1 || true");
        commands.add("echo '[IPv6 DNS NAT OUTPUT]'");
        commands.add(ip6tables + " -t nat -S OUTPUT 2>&1 | grep 'afwall-dns6' || true");
        commands.add("echo '[IPv6 DNS NAT chains]'");
        commands.add(ip6tables + " -t nat -S " + CHAIN_V6 + " 2>&1 || true");
        commands.add(ip6tables + " -t nat -S " + CHAIN_V6_PRE + " 2>&1 || true");
        commands.add("echo '[DNS boot persistence]'");
        commands.add("for f in /data/adb/service.d/" + BOOT_SCRIPT
                + " /su/su.d/" + BOOT_SCRIPT
                + " /system/su.d/" + BOOT_SCRIPT
                + " /system/etc/init.d/" + BOOT_SCRIPT
                + "; do if [ -f \"$f\" ]; then ls -l \"$f\"; fi; done");
        return commands;
    }

    private static void failSupervisorAction(Context context, RootCommand.Callback callback, String message) {
        ApplicationErrorLog.add(context, message);
        if (callback == null) {
            return;
        }
        RootCommand state = new RootCommand();
        state.exitCode = 1;
        state.res = new StringBuilder(message).append('\n');
        callback.cbFunc(state);
    }

    private static String queryControl(Context context, String command) {
        File socketFile = new File(workDir(context), SOCKET);
        if (!socketFile.exists()) {
            return "control socket missing\n";
        }
        try (LocalSocket socket = new LocalSocket()) {
            socket.setSoTimeout(1500);
            socket.connect(new LocalSocketAddress(socketFile.getAbsolutePath(), LocalSocketAddress.Namespace.FILESYSTEM));
            OutputStream output = socket.getOutputStream();
            output.write((command + "\n").getBytes(StandardCharsets.UTF_8));
            output.flush();
            socket.shutdownOutput();

            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            InputStream input = socket.getInputStream();
            byte[] chunk = new byte[4096];
            int read;
            while ((read = input.read(chunk)) != -1) {
                buffer.write(chunk, 0, read);
            }
            String result = buffer.toString("UTF-8");
            return result.trim().isEmpty() ? "empty response\n" : result;
        } catch (IOException e) {
            return "control socket error: " + e.getMessage() + "\n";
        }
    }

    private static List<QueryEntry> parseQueryEntries(String raw) {
        List<QueryEntry> entries = new ArrayList<>();
        if (raw == null) {
            return entries;
        }
        String[] lines = raw.split("\\r?\\n");
        for (String line : lines) {
            QueryEntry entry = QueryEntry.parse(line);
            if (entry != null) {
                entries.add(entry);
            }
        }
        return entries;
    }

    private static Map<String, String> parseKeyValueLines(String raw) {
        Map<String, String> values = new HashMap<>();
        if (raw == null) {
            return values;
        }
        String[] lines = raw.split("\\r?\\n");
        for (String line : lines) {
            if (line == null) {
                continue;
            }
            int separator = line.indexOf('=');
            if (separator <= 0) {
                continue;
            }
            String key = line.substring(0, separator).trim();
            String value = line.substring(separator + 1).trim();
            if (!key.isEmpty()) {
                values.put(key, value);
            }
        }
        return values;
    }

    private static Map<String, String> parseExtras(String[] parts, int startIndex) {
        Map<String, String> values = new HashMap<>();
        if (parts == null || parts.length <= startIndex) {
            return values;
        }
        for (int i = startIndex; i < parts.length; i++) {
            String part = parts[i];
            if (part == null) {
                continue;
            }
            int separator = part.indexOf('=');
            if (separator <= 0 || separator >= part.length() - 1) {
                continue;
            }
            values.put(part.substring(0, separator), part.substring(separator + 1));
        }
        return values;
    }

    private static String firstValue(Map<String, String> preferred,
                                     Map<String, String> fallback,
                                     String key) {
        String value = preferred.get(key);
        if (value == null || value.trim().isEmpty()) {
            value = fallback.get(key);
        }
        return value == null ? "" : value.trim();
    }

    private static long parseLong(String value, long fallback) {
        if (value == null || value.trim().isEmpty()) {
            return fallback;
        }
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static String emptyFallback(String value, String fallback) {
        return value == null || value.trim().isEmpty() ? fallback : value.trim();
    }

    private static String qtypeName(String value) {
        long numeric = parseLong(value, -1L);
        if (numeric == 1L) {
            return "A";
        }
        if (numeric == 2L) {
            return "NS";
        }
        if (numeric == 5L) {
            return "CNAME";
        }
        if (numeric == 15L) {
            return "MX";
        }
        if (numeric == 16L) {
            return "TXT";
        }
        if (numeric == 28L) {
            return "AAAA";
        }
        if (numeric == 33L) {
            return "SRV";
        }
        if (numeric == 65L) {
            return "HTTPS";
        }
        return numeric > 0L ? String.valueOf(numeric) : "unknown";
    }

    private static String sanitizeHistoryFilter(String filter) {
        if (filter == null) {
            return "";
        }
        String clean = filter.trim().replace('\n', ' ').replace('\r', ' ');
        clean = clean.replaceAll("\\s+", " ");
        if (clean.length() > 80) {
            clean = clean.substring(0, 80);
        }
        return clean;
    }

    private static String benchmarkUpstreamsDirect() {
        StringBuilder out = new StringBuilder();
        List<UpstreamTarget> targets = parseUpstreamTargets(G.dnsHijackUpstreams());
        int timeoutMs = Math.min(Math.max(G.dnsHijackTimeoutMs(), 250), 1000);
        byte[] query = buildBenchmarkQuery();

        out.append("benchmark=1\n");
        out.append("source=app_direct_udp\n");
        out.append("upstreams=").append(targets.size()).append('\n');
        out.append("timeout_ms=").append(timeoutMs).append('\n');
        if (targets.isEmpty()) {
            out.append("error=no_upstreams_configured\n");
            return out.toString();
        }

        for (int i = 0; i < targets.size(); i++) {
            UpstreamTarget target = targets.get(i);
            long start = System.nanoTime();
            ProbeResult result = probeUpstreamDirect(target, timeoutMs, query);
            int latencyMs = (int) ((System.nanoTime() - start) / 1000000L);
            out.append("upstream[").append(i).append("]=")
                    .append(target.host).append(':').append(target.port)
                    .append(" protocol=").append(target.protocol)
                    .append(" status=").append(result.status)
                    .append(" latency_ms=").append(latencyMs)
                    .append(" rcode=").append(result.rcode)
                    .append(" bytes=").append(result.bytes)
                    .append('\n');
        }
        return out.toString();
    }

    private static ProbeResult probeUpstreamDirect(UpstreamTarget target, int timeoutMs, byte[] query) {
        if ("tcp".equals(target.protocol)) {
            return probeTcpUpstreamDirect(target, timeoutMs, query);
        }
        return probeUdpUpstreamDirect(target, timeoutMs, query);
    }

    private static ProbeResult probeUdpUpstreamDirect(UpstreamTarget target, int timeoutMs, byte[] query) {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(timeoutMs);
            InetAddress address = InetAddress.getByName(target.host);
            DatagramPacket request = new DatagramPacket(query, query.length, address, target.port);
            socket.send(request);
            byte[] response = new byte[512];
            DatagramPacket reply = new DatagramPacket(response, response.length);
            socket.receive(reply);
            int bytes = reply.getLength();
            return new ProbeResult("ok", bytes, bytes >= 4 ? response[3] & 0x0f : -1);
        } catch (SocketTimeoutException e) {
            return new ProbeResult("timeout", -1, -1);
        } catch (IOException | RuntimeException e) {
            return new ProbeResult("error", -1, -1);
        }
    }

    private static ProbeResult probeTcpUpstreamDirect(UpstreamTarget target, int timeoutMs, byte[] query) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(InetAddress.getByName(target.host), target.port), timeoutMs);
            socket.setSoTimeout(timeoutMs);
            OutputStream output = socket.getOutputStream();
            output.write((query.length >> 8) & 0xff);
            output.write(query.length & 0xff);
            output.write(query);
            output.flush();
            InputStream input = socket.getInputStream();
            int high = input.read();
            int low = input.read();
            if (high < 0 || low < 0) {
                return new ProbeResult("error", -1, -1);
            }
            int expected = (high << 8) | low;
            if (expected <= 0 || expected > 4096) {
                return new ProbeResult("error", -1, -1);
            }
            byte[] response = new byte[expected];
            int read = readFully(input, response, expected);
            return new ProbeResult(read == expected ? "ok" : "error",
                    read, read >= 4 ? response[3] & 0x0f : -1);
        } catch (SocketTimeoutException e) {
            return new ProbeResult("timeout", -1, -1);
        } catch (IOException | RuntimeException e) {
            return new ProbeResult("error", -1, -1);
        }
    }

    private static int readFully(InputStream input, byte[] response, int expected) throws IOException {
        int offset = 0;
        while (offset < expected) {
            int read = input.read(response, offset, expected - offset);
            if (read < 0) {
                break;
            }
            offset += read;
        }
        return offset;
    }

    private static byte[] buildBenchmarkQuery() {
        byte[] query = new byte[] {
                0x42, 0x53, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                0x03, 'c', 'o', 'm',
                0x00,
                0x00, 0x01,
                0x00, 0x01
        };
        int id = (int) (System.currentTimeMillis() & 0xffff);
        query[0] = (byte) ((id >> 8) & 0xff);
        query[1] = (byte) (id & 0xff);
        return query;
    }

    private static List<UpstreamTarget> parseUpstreamTargets(String raw) {
        List<UpstreamTarget> targets = new ArrayList<>();
        if (raw == null) {
            return targets;
        }
        String[] lines = raw.split("[\\r\\n,]+");
        for (String line : lines) {
            UpstreamTarget target = UpstreamTarget.parse(line);
            if (target != null) {
                targets.add(target);
            }
        }
        return targets;
    }

    private static void appendFileInfo(StringBuilder out, String label, File file) {
        out.append(label).append('=').append(file.getAbsolutePath());
        out.append(" exists=").append(file.exists());
        if (file.exists()) {
            out.append(" size=").append(file.length());
            out.append(" canExecute=").append(file.canExecute());
        }
        out.append('\n');
    }

    private static void appendSmallFileValue(StringBuilder out, String label, File file) {
        out.append(label).append('=');
        if (!file.exists()) {
            out.append("missing\n");
            return;
        }
        try (FileInputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[256];
            int read = input.read(buffer);
            if (read <= 0) {
                out.append("empty\n");
            } else {
                out.append(new String(buffer, 0, read, StandardCharsets.UTF_8).trim()).append('\n');
            }
        } catch (IOException e) {
            out.append("unreadable: ").append(e.getMessage()).append('\n');
        }
    }

    private static String normalizeSupervisorAction(String action) {
        if ("start".equals(action) || "stop".equals(action)
                || "restart".equals(action) || "reload".equals(action)
                || "status".equals(action)) {
            return action;
        }
        return null;
    }

    private static long temporaryRuleExpiresAt() {
        return (System.currentTimeMillis() / 1000L) + TEMP_RULE_DURATION_SECONDS;
    }

    private static int countLines(String raw) {
        int count = 0;
        if (raw == null || raw.trim().isEmpty()) {
            return 0;
        }
        String[] lines = raw.split("\\r?\\n");
        for (String line : lines) {
            if (line != null && !line.trim().isEmpty()) {
                count++;
            }
        }
        return count;
    }

    private static void logRedirectPolicy(Context context, String prefix) {
        int captureCount = parseUidList(G.dnsHijackCaptureUids()).size();
        int bypassCount = parseUidList(G.dnsHijackBypassUids()).size();
        int captureInterfaceCount = parseInterfaceList(G.dnsHijackCaptureInterfaces()).size();
        int bypassInterfaceCount = parseInterfaceList(G.dnsHijackBypassInterfaces()).size();
        if (captureCount > 0 || bypassCount > 0
                || captureInterfaceCount > 0 || bypassInterfaceCount > 0) {
            ApplicationErrorLog.add(context, prefix + ": capture_uids=" + captureCount
                    + " bypass_uids=" + bypassCount
                    + " capture_interfaces=" + captureInterfaceCount
                    + " bypass_interfaces=" + bypassInterfaceCount);
        }
    }

    private static boolean appendOutputPolicyRules(List<String> commands, String appendCommand, int port) {
        List<Integer> bypassUids = parseUidList(G.dnsHijackBypassUids());
        List<Integer> captureUids = parseUidList(G.dnsHijackCaptureUids());
        List<String> bypassInterfaces = parseInterfaceList(G.dnsHijackBypassInterfaces());
        List<String> captureInterfaces = parseInterfaceList(G.dnsHijackCaptureInterfaces());
        for (String iface : bypassInterfaces) {
            commands.add(appendCommand + " -o " + iface + " -j RETURN");
        }
        for (Integer uid : bypassUids) {
            commands.add(appendCommand + " -m owner --uid-owner " + uid + " -j RETURN");
        }
        if (captureUids.isEmpty() && captureInterfaces.isEmpty()) {
            return false;
        }
        if (captureUids.isEmpty()) {
            for (String iface : captureInterfaces) {
                appendOutputRedirect(commands, appendCommand, port, null, iface);
            }
        } else if (captureInterfaces.isEmpty()) {
            for (Integer uid : captureUids) {
                if (!bypassUids.contains(uid)) {
                    appendOutputRedirect(commands, appendCommand, port, uid, null);
                }
            }
        } else {
            for (String iface : captureInterfaces) {
                if (bypassInterfaces.contains(iface)) {
                    continue;
                }
                for (Integer uid : captureUids) {
                    if (!bypassUids.contains(uid)) {
                        appendOutputRedirect(commands, appendCommand, port, uid, iface);
                    }
                }
            }
        }
        commands.add(appendCommand + " -j RETURN");
        return true;
    }

    private static void appendOutputRedirect(List<String> commands, String appendCommand,
                                             int port, Integer uid, String iface) {
        String matcher = "";
        if (iface != null) {
            matcher += " -o " + iface;
        }
        if (uid != null) {
            matcher += " -m owner --uid-owner " + uid;
        }
        commands.add(appendCommand + matcher + " -p udp --dport 53 -j REDIRECT --to-ports " + port);
        commands.add(appendCommand + matcher + " -p tcp --dport 53 -j REDIRECT --to-ports " + port);
    }

    private static boolean appendPreroutingPolicyRules(List<String> commands, String appendCommand, int port) {
        List<String> bypassInterfaces = parseInterfaceList(G.dnsHijackBypassInterfaces());
        List<String> captureInterfaces = parseInterfaceList(G.dnsHijackCaptureInterfaces());
        for (String iface : bypassInterfaces) {
            commands.add(appendCommand + " -i " + iface + " -j RETURN");
        }
        if (captureInterfaces.isEmpty()) {
            return false;
        }
        for (String iface : captureInterfaces) {
            if (bypassInterfaces.contains(iface)) {
                continue;
            }
            commands.add(appendCommand + " -i " + iface + " -p udp --dport 53 -j REDIRECT --to-ports " + port);
            commands.add(appendCommand + " -i " + iface + " -p tcp --dport 53 -j REDIRECT --to-ports " + port);
        }
        commands.add(appendCommand + " -j RETURN");
        return true;
    }

    private static String buildBootOutputRedirectRules(String tool, String chainVariable) {
        StringBuilder script = new StringBuilder();
        List<Integer> bypassUids = parseUidList(G.dnsHijackBypassUids());
        List<Integer> captureUids = parseUidList(G.dnsHijackCaptureUids());
        List<String> bypassInterfaces = parseInterfaceList(G.dnsHijackBypassInterfaces());
        List<String> captureInterfaces = parseInterfaceList(G.dnsHijackCaptureInterfaces());
        for (String iface : bypassInterfaces) {
            script.append("  ").append(tool).append(" -t nat -A \"")
                    .append(chainVariable).append("\" -o ")
                    .append(iface).append(" -j RETURN >> \"$LOG\" 2>&1\n");
        }
        for (Integer uid : bypassUids) {
            script.append("  ").append(tool).append(" -t nat -A \"")
                    .append(chainVariable).append("\" -m owner --uid-owner ")
                    .append(uid).append(" -j RETURN >> \"$LOG\" 2>&1\n");
        }
        if (captureUids.isEmpty() && captureInterfaces.isEmpty()) {
            script.append("  ").append(tool).append(" -t nat -A \"")
                    .append(chainVariable)
                    .append("\" -p udp --dport 53 -j REDIRECT --to-ports \"$PORT\" >> \"$LOG\" 2>&1\n");
            script.append("  ").append(tool).append(" -t nat -A \"")
                    .append(chainVariable)
                    .append("\" -p tcp --dport 53 -j REDIRECT --to-ports \"$PORT\" >> \"$LOG\" 2>&1\n");
            return script.toString();
        }
        if (captureUids.isEmpty()) {
            for (String iface : captureInterfaces) {
                appendBootOutputRedirect(script, tool, chainVariable, null, iface);
            }
        } else if (captureInterfaces.isEmpty()) {
            for (Integer uid : captureUids) {
                if (!bypassUids.contains(uid)) {
                    appendBootOutputRedirect(script, tool, chainVariable, uid, null);
                }
            }
        } else {
            for (String iface : captureInterfaces) {
                if (bypassInterfaces.contains(iface)) {
                    continue;
                }
                for (Integer uid : captureUids) {
                    if (!bypassUids.contains(uid)) {
                        appendBootOutputRedirect(script, tool, chainVariable, uid, iface);
                    }
                }
            }
        }
        script.append("  ").append(tool).append(" -t nat -A \"")
                .append(chainVariable).append("\" -j RETURN >> \"$LOG\" 2>&1\n");
        return script.toString();
    }

    private static void appendBootOutputRedirect(StringBuilder script, String tool,
                                                 String chainVariable, Integer uid, String iface) {
        String matcher = "";
        if (iface != null) {
            matcher += " -o " + iface;
        }
        if (uid != null) {
            matcher += " -m owner --uid-owner " + uid;
        }
        script.append("  ").append(tool).append(" -t nat -A \"")
                .append(chainVariable).append("\"").append(matcher)
                .append(" -p udp --dport 53 -j REDIRECT --to-ports \"$PORT\" >> \"$LOG\" 2>&1\n");
        script.append("  ").append(tool).append(" -t nat -A \"")
                .append(chainVariable).append("\"").append(matcher)
                .append(" -p tcp --dport 53 -j REDIRECT --to-ports \"$PORT\" >> \"$LOG\" 2>&1\n");
    }

    private static String buildBootPreroutingRedirectRules(String tool, String chainVariable) {
        StringBuilder script = new StringBuilder();
        List<String> bypassInterfaces = parseInterfaceList(G.dnsHijackBypassInterfaces());
        List<String> captureInterfaces = parseInterfaceList(G.dnsHijackCaptureInterfaces());
        for (String iface : bypassInterfaces) {
            script.append("  ").append(tool).append(" -t nat -A \"")
                    .append(chainVariable).append("\" -i ")
                    .append(iface).append(" -j RETURN >> \"$LOG\" 2>&1\n");
        }
        if (captureInterfaces.isEmpty()) {
            script.append("  ").append(tool).append(" -t nat -A \"")
                    .append(chainVariable)
                    .append("\" -p udp --dport 53 -j REDIRECT --to-ports \"$PORT\" >> \"$LOG\" 2>&1\n");
            script.append("  ").append(tool).append(" -t nat -A \"")
                    .append(chainVariable)
                    .append("\" -p tcp --dport 53 -j REDIRECT --to-ports \"$PORT\" >> \"$LOG\" 2>&1\n");
            return script.toString();
        }
        for (String iface : captureInterfaces) {
            if (bypassInterfaces.contains(iface)) {
                continue;
            }
            script.append("  ").append(tool).append(" -t nat -A \"")
                    .append(chainVariable).append("\" -i ").append(iface)
                    .append(" -p udp --dport 53 -j REDIRECT --to-ports \"$PORT\" >> \"$LOG\" 2>&1\n");
            script.append("  ").append(tool).append(" -t nat -A \"")
                    .append(chainVariable).append("\" -i ").append(iface)
                    .append(" -p tcp --dport 53 -j REDIRECT --to-ports \"$PORT\" >> \"$LOG\" 2>&1\n");
        }
        script.append("  ").append(tool).append(" -t nat -A \"")
                .append(chainVariable).append("\" -j RETURN >> \"$LOG\" 2>&1\n");
        return script.toString();
    }

    private static List<Integer> parseUidList(String raw) {
        List<Integer> uids = new ArrayList<>();
        if (raw == null || raw.trim().isEmpty()) {
            return uids;
        }
        String[] lines = raw.split("\\r?\\n");
        for (String line : lines) {
            if (line == null) {
                continue;
            }
            int comment = line.indexOf('#');
            String clean = comment >= 0 ? line.substring(0, comment) : line;
            String[] tokens = clean.trim().split("[\\s,|]+");
            for (String token : tokens) {
                if (token == null || token.trim().isEmpty()) {
                    continue;
                }
                try {
                    long parsed = Long.parseLong(token.trim());
                    if (parsed > 0 && parsed <= Integer.MAX_VALUE) {
                        Integer uid = (int) parsed;
                        if (!uids.contains(uid)) {
                            uids.add(uid);
                        }
                    }
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return uids;
    }

    private static List<String> parseInterfaceList(String raw) {
        List<String> interfaces = new ArrayList<>();
        if (raw == null || raw.trim().isEmpty()) {
            return interfaces;
        }
        String[] lines = raw.split("\\r?\\n");
        for (String line : lines) {
            if (line == null) {
                continue;
            }
            int comment = line.indexOf('#');
            String clean = comment >= 0 ? line.substring(0, comment) : line;
            String[] tokens = clean.trim().split("[\\s,|]+");
            for (String token : tokens) {
                String iface = token == null ? "" : token.trim();
                if (iface.matches("[A-Za-z0-9_.:-]{1,31}\\+?")
                        && !interfaces.contains(iface)) {
                    interfaces.add(iface);
                }
            }
        }
        return interfaces;
    }

    public static final class QueryEntry {
        public final long timestamp;
        public final String action;
        public final String domain;
        public final String latency;
        public final String transport;
        public final String qtype;
        public final String result;
        public final String rule;
        public final String upstream;

        private QueryEntry(long timestamp, String action, String domain, String latency,
                           String transport, String qtype, String result, String rule,
                           String upstream) {
            this.timestamp = timestamp;
            this.action = action;
            this.domain = domain;
            this.latency = latency;
            this.transport = emptyFallback(transport, "unknown");
            this.qtype = qtypeName(emptyFallback(qtype, "0"));
            this.result = emptyFallback(result, action);
            this.rule = emptyFallback(rule, action);
            this.upstream = emptyFallback(upstream, "unknown");
        }

        private static QueryEntry parse(String line) {
            if (line == null) {
                return null;
            }
            String[] parts = line.trim().split("\\s+");
            if (parts.length < 4) {
                return null;
            }
            try {
                long timestamp = Long.parseLong(parts[0]);
                String action = parts[1];
                String domain = normalizeDomain(parts[2]);
                if (domain.isEmpty()) {
                    return null;
                }
                Map<String, String> extras = parseExtras(parts, 4);
                return new QueryEntry(timestamp, action, domain, parts[3],
                        extras.get("transport"), extras.get("qtype"),
                        extras.get("result"), extras.get("rule"),
                        extras.get("upstream"));
            } catch (NumberFormatException e) {
                return null;
            }
        }

        public boolean hasDomain() {
            return domain != null && !domain.isEmpty() && !"unknown".equals(domain);
        }

        public String displayLine() {
            return timestamp + "  " + action + "  " + domain + "  " + latency
                    + "  transport=" + transport
                    + "  qtype=" + qtype
                    + "  result=" + result
                    + "  rule=" + rule
                    + "  upstream=" + upstream;
        }
    }

    public static final class DnsDashboardSnapshot {
        public final String statusLine;
        public final String detailLine;

        private DnsDashboardSnapshot(String statusLine, String detailLine) {
            this.statusLine = statusLine;
            this.detailLine = detailLine;
        }
    }

    private static final class ProbeResult {
        private final String status;
        private final int bytes;
        private final int rcode;

        private ProbeResult(String status, int bytes, int rcode) {
            this.status = status;
            this.bytes = bytes;
            this.rcode = rcode;
        }
    }

    private static final class UpstreamTarget {
        private final String host;
        private final int port;
        private final String protocol;

        private UpstreamTarget(String host, int port, String protocol) {
            this.host = host;
            this.port = port;
            this.protocol = protocol;
        }

        private static UpstreamTarget parse(String raw) {
            if (raw == null) {
                return null;
            }
            String value = raw.trim();
            String host = value;
            int port = 53;
            String protocol = "auto";
            if (value.isEmpty() || value.startsWith("#")) {
                return null;
            }
            if (value.regionMatches(true, 0, "udp://", 0, 6)) {
                protocol = "udp";
                value = value.substring(6).trim();
                host = value;
            } else if (value.regionMatches(true, 0, "tcp://", 0, 6)) {
                protocol = "tcp";
                value = value.substring(6).trim();
                host = value;
            }
            if (value.startsWith("[") && value.contains("]")) {
                int end = value.indexOf(']');
                host = value.substring(1, end);
                if (end + 2 < value.length() && value.charAt(end + 1) == ':') {
                    port = parsePort(value.substring(end + 2), port);
                }
            } else {
                int firstColon = value.indexOf(':');
                int lastColon = value.lastIndexOf(':');
                if (firstColon > 0 && firstColon == lastColon) {
                    host = value.substring(0, firstColon);
                    port = parsePort(value.substring(firstColon + 1), port);
                }
            }
            host = host.trim();
            if (host.isEmpty()) {
                return null;
            }
            return new UpstreamTarget(host, port, protocol);
        }

        private static int parsePort(String raw, int fallback) {
            try {
                int parsed = Integer.parseInt(raw.trim());
                return parsed > 0 && parsed <= 65535 ? parsed : fallback;
            } catch (NumberFormatException e) {
                return fallback;
            }
        }
    }

    private static String normalizeDomain(String raw) {
        if (raw == null) {
            return "";
        }
        String domain = raw.trim().toLowerCase(Locale.US);
        domain = domain.replaceFirst("^\\*\\.", "");
        domain = domain.replaceFirst("^\\.", "");
        domain = domain.replaceFirst("\\.$", "");
        if (!domain.matches("^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")) {
            return "";
        }
        return domain;
    }

    private static void appendBootPersistenceCommand(Context context, List<String> commands) {
        if (!G.dnsHijackBootPersistence()) {
            appendRemoveBootPersistenceCommand(commands);
            return;
        }
        File bootScript = new File(workDir(context), BOOT_SCRIPT);
        commands.add("#LITERAL# " + buildInstallBootPersistenceCommand(bootScript));
        ApplicationErrorLog.add(context, "DNS hijacker boot persistence install queued");
    }

    private static String buildInstallBootPersistenceCommand(File bootScript) {
        return "SRC=" + shellQuote(bootScript.getAbsolutePath()) + "; "
                + "NAME=" + shellQuote(BOOT_SCRIPT) + "; "
                + "installed=0; "
                + "for DIR in /data/adb/service.d /su/su.d /system/su.d /system/etc/init.d; do "
                + "if [ -d \"$DIR\" ]; then "
                + "cp \"$SRC\" \"$DIR/$NAME\" 2>/dev/null && chmod 755 \"$DIR/$NAME\" 2>/dev/null "
                + "&& echo \"DNS boot persistence installed at $DIR/$NAME\" && installed=1 && break; "
                + "fi; "
                + "done; "
                + "if [ \"$installed\" = 0 ] && [ -d /data/adb ]; then "
                + "mkdir -p /data/adb/service.d 2>/dev/null "
                + "&& cp \"$SRC\" /data/adb/service.d/\"$NAME\" 2>/dev/null "
                + "&& chmod 755 /data/adb/service.d/\"$NAME\" 2>/dev/null "
                + "&& echo \"DNS boot persistence installed at /data/adb/service.d/$NAME\" "
                + "&& installed=1; "
                + "fi; "
                + "if [ \"$installed\" = 0 ]; then echo 'DNS boot persistence: no supported root boot directory found'; fi; "
                + "true";
    }

    private static String buildRemoveBootPersistenceCommand() {
        return "for FILE in /data/adb/service.d/" + BOOT_SCRIPT
                + " /su/su.d/" + BOOT_SCRIPT
                + " /system/su.d/" + BOOT_SCRIPT
                + " /system/etc/init.d/" + BOOT_SCRIPT
                + "; do [ -e \"$FILE\" ] && rm -f \"$FILE\" 2>/dev/null; done; true";
    }

    private static void appendRemoveBootPersistenceCommand(List<String> commands) {
        commands.add("#LITERAL# " + buildRemoveBootPersistenceCommand());
    }

    private static List<String> buildRootRepairCommands(Context context) {
        List<String> commands = new ArrayList<>();
        File bootScript = new File(workDir(context), BOOT_SCRIPT);
        commands.add(shellQuote(supervisorPath(context)) + " start");
        logRedirectPolicy(context, "DNS redirect policy repair queued");
        appendRootRedirectRepairCommands(context, commands, false);
        if (G.enableIPv6()) {
            appendRootRedirectRepairCommands(context, commands, true);
        }
        if (G.dnsHijackBootPersistence()) {
            commands.add(buildInstallBootPersistenceCommand(bootScript));
        } else {
            commands.add(buildRemoveBootPersistenceCommand());
        }
        return commands;
    }

    private static void appendRootRedirectRepairCommands(Context context, List<String> commands, boolean ipv6) {
        String iptables = shellQuote(Api.getBinaryPath(context, ipv6));
        int port = G.dnsHijackPort(DEFAULT_PORT);
        String chain = ipv6 ? CHAIN_V6 : CHAIN_V4;
        String preChain = ipv6 ? CHAIN_V6_PRE : CHAIN_V4_PRE;

        commands.add(iptables + " -t nat -D OUTPUT -p udp --dport 53 -j " + chain + " >/dev/null 2>&1 || true");
        commands.add(iptables + " -t nat -D OUTPUT -p tcp --dport 53 -j " + chain + " >/dev/null 2>&1 || true");
        commands.add(iptables + " -t nat -D PREROUTING -p udp --dport 53 -j " + preChain + " >/dev/null 2>&1 || true");
        commands.add(iptables + " -t nat -D PREROUTING -p tcp --dport 53 -j " + preChain + " >/dev/null 2>&1 || true");
        commands.add(iptables + " -t nat -N " + chain + " >/dev/null 2>&1 || true");
        commands.add(iptables + " -t nat -N " + preChain + " >/dev/null 2>&1 || true");
        commands.add(iptables + " -t nat -F " + chain);
        commands.add(iptables + " -t nat -F " + preChain);
        commands.add(iptables + " -t nat -A " + chain + " -o lo -j RETURN");
        commands.add(iptables + " -t nat -A " + chain + " -m owner --uid-owner 0 -j RETURN");
        if (!appendOutputPolicyRules(commands, iptables + " -t nat -A " + chain, port)) {
            commands.add(iptables + " -t nat -A " + chain + " -p udp --dport 53 -j REDIRECT --to-ports " + port);
            commands.add(iptables + " -t nat -A " + chain + " -p tcp --dport 53 -j REDIRECT --to-ports " + port);
        }
        commands.add(iptables + " -t nat -A " + preChain + " -i lo -j RETURN");
        if (!appendPreroutingPolicyRules(commands, iptables + " -t nat -A " + preChain, port)) {
            commands.add(iptables + " -t nat -A " + preChain + " -p udp --dport 53 -j REDIRECT --to-ports " + port);
            commands.add(iptables + " -t nat -A " + preChain + " -p tcp --dport 53 -j REDIRECT --to-ports " + port);
        }
        commands.add(iptables + " -t nat -I OUTPUT 1 -p udp --dport 53 -j " + chain);
        commands.add(iptables + " -t nat -I OUTPUT 1 -p tcp --dport 53 -j " + chain);
        commands.add(iptables + " -t nat -I PREROUTING 1 -p udp --dport 53 -j " + preChain);
        commands.add(iptables + " -t nat -I PREROUTING 1 -p tcp --dport 53 -j " + preChain);
    }

    private static void appendRedirectRules(List<String> commands, boolean ipv6) {
        int port = G.dnsHijackPort(DEFAULT_PORT);
        String chain = ipv6 ? CHAIN_V6 : CHAIN_V4;
        String preChain = ipv6 ? CHAIN_V6_PRE : CHAIN_V4_PRE;

        commands.add("#NOCHK# -t nat -N " + chain);
        commands.add("#NOCHK# -t nat -N " + preChain);
        commands.add("#NOCHK# -t nat -F " + chain);
        commands.add("#NOCHK# -t nat -F " + preChain);

        commands.add("#NOCHK# -t nat -A " + chain + " -o lo -j RETURN");
        commands.add("#NOCHK# -t nat -A " + chain + " -m owner --uid-owner 0 -j RETURN");
        if (!appendOutputPolicyRules(commands, "#NOCHK# -t nat -A " + chain, port)) {
            commands.add("#NOCHK# -t nat -A " + chain + " -p udp --dport 53 -j REDIRECT --to-ports " + port);
            commands.add("#NOCHK# -t nat -A " + chain + " -p tcp --dport 53 -j REDIRECT --to-ports " + port);
        }

        commands.add("#NOCHK# -t nat -A " + preChain + " -i lo -j RETURN");
        if (!appendPreroutingPolicyRules(commands, "#NOCHK# -t nat -A " + preChain, port)) {
            commands.add("#NOCHK# -t nat -A " + preChain + " -p udp --dport 53 -j REDIRECT --to-ports " + port);
            commands.add("#NOCHK# -t nat -A " + preChain + " -p tcp --dport 53 -j REDIRECT --to-ports " + port);
        }

        commands.add("#NOCHK# -t nat -I OUTPUT 1 -p udp --dport 53 -j " + chain);
        commands.add("#NOCHK# -t nat -I OUTPUT 1 -p tcp --dport 53 -j " + chain);
        commands.add("#NOCHK# -t nat -I PREROUTING 1 -p udp --dport 53 -j " + preChain);
        commands.add("#NOCHK# -t nat -I PREROUTING 1 -p tcp --dport 53 -j " + preChain);
    }

    private static void appendPurgeRules(List<String> commands, boolean ipv6) {
        String chain = ipv6 ? CHAIN_V6 : CHAIN_V4;
        String preChain = ipv6 ? CHAIN_V6_PRE : CHAIN_V4_PRE;

        commands.add("#NOCHK# -t nat -D OUTPUT -p udp --dport 53 -j " + chain);
        commands.add("#NOCHK# -t nat -D OUTPUT -p tcp --dport 53 -j " + chain);
        commands.add("#NOCHK# -t nat -D PREROUTING -p udp --dport 53 -j " + preChain);
        commands.add("#NOCHK# -t nat -D PREROUTING -p tcp --dport 53 -j " + preChain);
        commands.add("#NOCHK# -t nat -F " + chain);
        commands.add("#NOCHK# -t nat -F " + preChain);
        commands.add("#NOCHK# -t nat -X " + chain);
        commands.add("#NOCHK# -t nat -X " + preChain);
    }

    private static void appendStopCommand(Context context, List<String> commands) {
        if (context == null) {
            return;
        }
        File supervisor = new File(workDir(context), SUPERVISOR);
        if (supervisor.exists()) {
            commands.add("#LITERAL# " + shellQuote(supervisor.getAbsolutePath()) + " stop || true");
        }
    }

    private static boolean prepareDaemon(Context context) {
        if (context == null) {
            return false;
        }

        try {
            File dir = workDir(context);
            if (!dir.exists() && !dir.mkdirs()) {
                throw new IOException("Unable to create " + dir.getAbsolutePath());
            }

            File daemon = new File(dir, DAEMON_NAME);
            copyDaemonAsset(context, daemon);
            if (!daemon.setExecutable(true, false)) {
                Log.w(TAG, "Unable to mark daemon executable from app context; root start will chmod it");
            }

            writeText(new File(dir, CONF), buildConfig(context));
            File supervisor = new File(dir, SUPERVISOR);
            writeText(supervisor, buildSupervisorScript(dir, daemon));
            if (!supervisor.setExecutable(true, false)) {
                Log.w(TAG, "Unable to mark supervisor executable from app context; root start will chmod it");
            }
            File bootScript = new File(dir, BOOT_SCRIPT);
            writeText(bootScript, buildBootScript(context, dir));
            if (!bootScript.setExecutable(true, false)) {
                Log.w(TAG, "Unable to mark DNS boot script executable from app context; root install will chmod it");
            }
            return true;
        } catch (IOException e) {
            Log.e(TAG, "Unable to prepare DNS daemon", e);
            ApplicationErrorLog.add(context, "Unable to prepare DNS hijacker daemon: " + e.getMessage());
            return false;
        }
    }

    private static void copyDaemonAsset(Context context, File target) throws IOException {
        String abi = selectAbi();
        String asset = "dnsd/" + abi + "/" + DAEMON_NAME;
        try (InputStream input = context.getAssets().open(asset);
             FileOutputStream output = new FileOutputStream(target, false)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) != -1) {
                output.write(buffer, 0, read);
            }
        }
    }

    private static String buildConfig(Context context) {
        File dir = workDir(context);
        StringBuilder config = new StringBuilder();
        G.pruneExpiredDnsHijackTemporaryRules();
        config.append("port=").append(G.dnsHijackPort(DEFAULT_PORT)).append('\n');
        config.append("control_socket=").append(new File(dir, SOCKET).getAbsolutePath()).append('\n');
        config.append("pid_file=").append(new File(dir, PID).getAbsolutePath()).append('\n');
        config.append("log_file=").append(new File(dir, QUERY_LOG).getAbsolutePath()).append('\n');
        config.append("fail_open=").append(G.dnsHijackFailOpen() ? "1" : "0").append('\n');
        config.append("strict_mode=").append(G.dnsHijackStrictMode() ? "1" : "0").append('\n');
        config.append("timeout_ms=").append(G.dnsHijackTimeoutMs()).append('\n');
        config.append("cache_size=").append(G.dnsHijackCacheSize()).append('\n');

        appendConfigEntries(config, "upstream", G.dnsHijackUpstreams());
        appendConfigEntries(config, "split_upstream", G.dnsHijackSplitUpstreams());
        appendConfigEntries(config, "allow_exact", G.dnsHijackAllowExact());
        appendConfigEntries(config, "allow_suffix", G.dnsHijackAllowSuffix());
        appendConfigEntries(config, "block_exact", G.dnsHijackBlockExact());
        appendConfigEntries(config, "block_suffix", G.dnsHijackBlockSuffix());
        appendConfigEntries(config, "allow_regex", G.dnsHijackAllowRegex());
        appendConfigEntries(config, "block_regex", G.dnsHijackBlockRegex());
        appendConfigEntries(config, "temp_allow", G.dnsHijackTempAllow());
        appendConfigEntries(config, "temp_block", G.dnsHijackTempBlock());
        appendConfigFile(config, "block_exact_file", DnsBlocklistManager.exactBlockFile(context));
        appendConfigFile(config, "block_suffix_file", DnsBlocklistManager.suffixBlockFile(context));

        return config.toString();
    }

    private static void appendConfigFile(StringBuilder config, String key, File file) {
        if (file.exists() && file.length() > 0) {
            config.append(key).append('=').append(file.getAbsolutePath()).append('\n');
        }
    }

    private static void appendConfigEntries(StringBuilder config, String key, String raw) {
        if (raw == null) {
            return;
        }
        String[] lines = raw.split("[\\r\\n,]+");
        for (String line : lines) {
            String value = line == null ? "" : line.trim();
            if (value.isEmpty() || value.startsWith("#")) {
                continue;
            }
            config.append(key).append('=').append(value.toLowerCase(Locale.US)).append('\n');
        }
    }

    private static String buildBootScript(Context context, File dir) {
        String supervisor = new File(dir, SUPERVISOR).getAbsolutePath();
        String log = new File(dir, BOOT_LOG).getAbsolutePath();
        String iptables = Api.getBinaryPath(context, false);
        String ip6tables = Api.getBinaryPath(context, true);
        int port = G.dnsHijackPort(DEFAULT_PORT);

        return "#!/system/bin/sh\n"
                + "PATH=/system/bin:/system/xbin:/vendor/bin:/sbin:/su/bin:/data/adb/magisk:$PATH\n"
                + "SUPERVISOR=" + shellQuote(supervisor) + "\n"
                + "IPTABLES=" + shellQuote(iptables) + "\n"
                + "IP6TABLES=" + shellQuote(ip6tables) + "\n"
                + "PORT=" + port + "\n"
                + "LOG=" + shellQuote(log) + "\n"
                + "CHAIN4=" + CHAIN_V4 + "\n"
                + "PRE4=" + CHAIN_V4_PRE + "\n"
                + "CHAIN6=" + CHAIN_V6 + "\n"
                + "PRE6=" + CHAIN_V6_PRE + "\n"
                + "log_msg() {\n"
                + "  echo \"$(date +%s) $*\" >> \"$LOG\" 2>/dev/null\n"
                + "}\n"
                + "ipt() {\n"
                + "  if [ -x \"$IPTABLES\" ]; then \"$IPTABLES\" \"$@\"; else iptables \"$@\"; fi\n"
                + "}\n"
                + "ip6t() {\n"
                + "  if [ -x \"$IP6TABLES\" ]; then \"$IP6TABLES\" \"$@\"; elif command -v ip6tables >/dev/null 2>&1; then ip6tables \"$@\"; else return 0; fi\n"
                + "}\n"
                + "restore_v4() {\n"
                + "  ipt -t nat -D OUTPUT -p udp --dport 53 -j \"$CHAIN4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -D OUTPUT -p tcp --dport 53 -j \"$CHAIN4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -D PREROUTING -p udp --dport 53 -j \"$PRE4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -D PREROUTING -p tcp --dport 53 -j \"$PRE4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -N \"$CHAIN4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -N \"$PRE4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -F \"$CHAIN4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -F \"$PRE4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -A \"$CHAIN4\" -o lo -j RETURN >> \"$LOG\" 2>&1\n"
                + "  ipt -t nat -A \"$CHAIN4\" -m owner --uid-owner 0 -j RETURN >> \"$LOG\" 2>&1\n"
                + buildBootOutputRedirectRules("ipt", "$CHAIN4")
                + "  ipt -t nat -A \"$PRE4\" -i lo -j RETURN >> \"$LOG\" 2>&1\n"
                + buildBootPreroutingRedirectRules("ipt", "$PRE4")
                + "  ipt -t nat -I OUTPUT 1 -p udp --dport 53 -j \"$CHAIN4\" >> \"$LOG\" 2>&1\n"
                + "  ipt -t nat -I OUTPUT 1 -p tcp --dport 53 -j \"$CHAIN4\" >> \"$LOG\" 2>&1\n"
                + "  ipt -t nat -I PREROUTING 1 -p udp --dport 53 -j \"$PRE4\" >> \"$LOG\" 2>&1\n"
                + "  ipt -t nat -I PREROUTING 1 -p tcp --dport 53 -j \"$PRE4\" >> \"$LOG\" 2>&1\n"
                + "}\n"
                + "restore_v6() {\n"
                + "  ip6t -t nat -D OUTPUT -p udp --dport 53 -j \"$CHAIN6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -D OUTPUT -p tcp --dport 53 -j \"$CHAIN6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -D PREROUTING -p udp --dport 53 -j \"$PRE6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -D PREROUTING -p tcp --dport 53 -j \"$PRE6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -N \"$CHAIN6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -N \"$PRE6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -F \"$CHAIN6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -F \"$PRE6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -A \"$CHAIN6\" -o lo -j RETURN >> \"$LOG\" 2>&1\n"
                + "  ip6t -t nat -A \"$CHAIN6\" -m owner --uid-owner 0 -j RETURN >> \"$LOG\" 2>&1\n"
                + buildBootOutputRedirectRules("ip6t", "$CHAIN6")
                + "  ip6t -t nat -A \"$PRE6\" -i lo -j RETURN >> \"$LOG\" 2>&1\n"
                + buildBootPreroutingRedirectRules("ip6t", "$PRE6")
                + "  ip6t -t nat -I OUTPUT 1 -p udp --dport 53 -j \"$CHAIN6\" >> \"$LOG\" 2>&1\n"
                + "  ip6t -t nat -I OUTPUT 1 -p tcp --dport 53 -j \"$CHAIN6\" >> \"$LOG\" 2>&1\n"
                + "  ip6t -t nat -I PREROUTING 1 -p udp --dport 53 -j \"$PRE6\" >> \"$LOG\" 2>&1\n"
                + "  ip6t -t nat -I PREROUTING 1 -p tcp --dport 53 -j \"$PRE6\" >> \"$LOG\" 2>&1\n"
                + "}\n"
                + "log_msg 'DNS boot restore starting'\n"
                + "sleep 15\n"
                + "if [ ! -x \"$SUPERVISOR\" ]; then log_msg 'supervisor missing or not executable'; exit 0; fi\n"
                + "\"$SUPERVISOR\" start >> \"$LOG\" 2>&1\n"
                + "restore_v4\n"
                + "restore_v6\n"
                + "log_msg 'DNS boot restore complete'\n";
    }

    private static String buildSupervisorScript(File dir, File daemon) {
        String marker = new File(dir, ENABLED_MARKER).getAbsolutePath();
        String config = new File(dir, CONF).getAbsolutePath();
        String pid = new File(dir, PID).getAbsolutePath();
        String log = new File(dir, SUPERVISOR_LOG).getAbsolutePath();
        String supervisorPid = new File(dir, SUPERVISOR_PID).getAbsolutePath();
        String restartCount = new File(dir, RESTART_COUNT).getAbsolutePath();
        String lastExit = new File(dir, LAST_EXIT).getAbsolutePath();

        return "#!/system/bin/sh\n"
                + "DIR=" + shellQuote(dir.getAbsolutePath()) + "\n"
                + "DAEMON=" + shellQuote(daemon.getAbsolutePath()) + "\n"
                + "CONF=" + shellQuote(config) + "\n"
                + "PID=" + shellQuote(pid) + "\n"
                + "SUP_PID=" + shellQuote(supervisorPid) + "\n"
                + "MARKER=" + shellQuote(marker) + "\n"
                + "LOG=" + shellQuote(log) + "\n"
                + "RESTARTS=" + shellQuote(restartCount) + "\n"
                + "LAST_EXIT=" + shellQuote(lastExit) + "\n"
                + "log_msg() {\n"
                + "  echo \"$(date +%s) $*\" >> \"$LOG\" 2>/dev/null\n"
                + "}\n"
                + "is_running() {\n"
                + "  [ -f \"$PID\" ] && kill -0 \"$(cat \"$PID\")\" 2>/dev/null\n"
                + "}\n"
                + "supervisor_running() {\n"
                + "  [ -f \"$SUP_PID\" ] && kill -0 \"$(cat \"$SUP_PID\")\" 2>/dev/null\n"
                + "}\n"
                + "increment_restarts() {\n"
                + "  count=$(cat \"$RESTARTS\" 2>/dev/null || echo 0)\n"
                + "  case \"$count\" in *[!0-9]*|'') count=0 ;; esac\n"
                + "  count=$((count + 1))\n"
                + "  echo \"$count\" > \"$RESTARTS\" 2>/dev/null\n"
                + "}\n"
                + "watch_loop() {\n"
                + "  trap 'rm -f \"$SUP_PID\"; exit 0' TERM INT\n"
                + "  log_msg 'watchdog started'\n"
                + "  while [ -f \"$MARKER\" ]; do\n"
                + "    if [ ! -x \"$DAEMON\" ]; then\n"
                + "      echo \"$(date +%s) missing_daemon\" > \"$LAST_EXIT\" 2>/dev/null\n"
                + "      log_msg 'daemon binary missing or not executable'\n"
                + "      sleep 5\n"
                + "      continue\n"
                + "    fi\n"
                + "    \"$DAEMON\" --config \"$CONF\" >> \"$LOG\" 2>&1\n"
                + "    exit_code=$?\n"
                + "    echo \"$(date +%s) exit=$exit_code\" > \"$LAST_EXIT\" 2>/dev/null\n"
                + "    if [ -f \"$MARKER\" ]; then\n"
                + "      increment_restarts\n"
                + "      log_msg \"daemon exited with $exit_code; restarting\"\n"
                + "      sleep 2\n"
                + "    fi\n"
                + "  done\n"
                + "  log_msg 'watchdog stopped'\n"
                + "  rm -f \"$SUP_PID\"\n"
                + "}\n"
                + "start_daemon() {\n"
                + "  mkdir -p \"$DIR\"\n"
                + "  chmod 700 \"$DIR\" 2>/dev/null || true\n"
                + "  chmod 755 \"$DAEMON\" 2>/dev/null || true\n"
                + "  touch \"$MARKER\"\n"
                + "  if is_running; then exit 0; fi\n"
                + "  if supervisor_running; then\n"
                + "    sleep 1\n"
                + "    if is_running; then exit 0; fi\n"
                + "    log_msg 'watchdog already running but daemon is not ready'\n"
                + "    exit 1\n"
                + "  fi\n"
                + "  ( watch_loop ) >/dev/null 2>&1 &\n"
                + "  echo \"$!\" > \"$SUP_PID\" 2>/dev/null\n"
                + "  sleep 1\n"
                + "  if is_running; then exit 0; fi\n"
                + "  exit 1\n"
                + "}\n"
                + "stop_daemon() {\n"
                + "  rm -f \"$MARKER\"\n"
                + "  if [ -f \"$PID\" ]; then kill -TERM \"$(cat \"$PID\")\" 2>/dev/null || true; fi\n"
                + "  if [ -f \"$SUP_PID\" ]; then kill -TERM \"$(cat \"$SUP_PID\")\" 2>/dev/null || true; fi\n"
                + "  rm -f \"$SUP_PID\"\n"
                + "}\n"
                + "case \"$1\" in\n"
                + "  start) start_daemon ;;\n"
                + "  stop) stop_daemon; exit 0 ;;\n"
                + "  restart) stop_daemon; start_daemon ;;\n"
                + "  reload) if is_running; then kill -HUP \"$(cat \"$PID\")\" 2>/dev/null; else start_daemon; fi ;;\n"
                + "  status) \n"
                + "    if is_running; then echo \"daemon=running pid=$(cat \"$PID\")\"; else echo daemon=stopped; fi\n"
                + "    if supervisor_running; then echo \"watchdog=running pid=$(cat \"$SUP_PID\")\"; else echo watchdog=stopped; fi\n"
                + "    echo \"restart_count=$(cat \"$RESTARTS\" 2>/dev/null || echo 0)\"\n"
                + "    echo \"last_exit=$(cat \"$LAST_EXIT\" 2>/dev/null || echo none)\"\n"
                + "    if is_running || supervisor_running; then exit 0; else exit 1; fi ;;\n"
                + "  *) echo \"usage: $0 {start|stop|restart|reload|status}\"; exit 2 ;;\n"
                + "esac\n";
    }

    private static File workDir(Context context) {
        return context.getApplicationContext().getDir(WORK_DIR, Context.MODE_PRIVATE);
    }

    private static String supervisorPath(Context context) {
        return new File(workDir(context), SUPERVISOR).getAbsolutePath();
    }

    private static void writeText(File file, String text) throws IOException {
        try (FileOutputStream output = new FileOutputStream(file, false)) {
            output.write(text.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static String selectAbi() {
        String[] abis = Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP
                ? Build.SUPPORTED_ABIS
                : new String[]{Build.CPU_ABI};
        for (String abi : abis) {
            if ("arm64-v8a".equals(abi) || "armeabi-v7a".equals(abi)
                    || "x86_64".equals(abi) || "x86".equals(abi)) {
                return abi;
            }
        }
        return "armeabi-v7a";
    }

    private static String shellQuote(String value) {
        if (value == null) {
            return "''";
        }
        return "'" + value.replace("'", "'\"'\"'") + "'";
    }
}
