package dev.ukanth.ufirewall.dns;

import android.content.Context;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Build;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

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
    private static final String CHAIN_V4 = "afwall-dns";
    private static final String CHAIN_V4_PRE = "afwall-dns-pre";
    private static final String CHAIN_V6 = "afwall-dns6";
    private static final String CHAIN_V6_PRE = "afwall-dns6-pre";
    private static final int DEFAULT_PORT = 5354;

    private DnsHijackManager() {
    }

    public static void appendApplyCommands(Context context, List<String> commands, boolean ipv6) {
        appendPurgeRules(commands, ipv6);
        if (!G.enableDnsHijack()) {
            if (!ipv6) {
                appendStopCommand(context, commands);
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
            commands.add("#LITERAL# " + shellQuote(supervisorPath(context)) + " start");
        }
        appendRedirectRules(commands, ipv6);
    }

    public static void appendPurgeCommands(Context context, List<String> commands, boolean ipv6) {
        appendPurgeRules(commands, ipv6);
        if (!ipv6) {
            appendStopCommand(context, commands);
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

        out.append("enabled_pref=").append(G.enableDnsHijack()).append('\n');
        out.append("port=").append(G.dnsHijackPort(DEFAULT_PORT)).append('\n');
        out.append("fail_open=").append(G.dnsHijackFailOpen()).append('\n');
        out.append("strict_mode=").append(G.dnsHijackStrictMode()).append('\n');
        out.append("timeout_ms=").append(G.dnsHijackTimeoutMs()).append('\n');
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

        out.append("\n[control status]\n");
        out.append(queryControl(context, "status"));
        out.append("\n[recent queries]\n");
        String logs = queryControl(context, "logs");
        out.append(logs.trim().isEmpty() ? "no daemon query logs reported\n" : logs);
        return out.toString();
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

    private static void appendFileInfo(StringBuilder out, String label, File file) {
        out.append(label).append('=').append(file.getAbsolutePath());
        out.append(" exists=").append(file.exists());
        if (file.exists()) {
            out.append(" size=").append(file.length());
            out.append(" canExecute=").append(file.canExecute());
        }
        out.append('\n');
    }

    private static String normalizeSupervisorAction(String action) {
        if ("start".equals(action) || "stop".equals(action)
                || "restart".equals(action) || "reload".equals(action)
                || "status".equals(action)) {
            return action;
        }
        return null;
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
        commands.add("#NOCHK# -t nat -A " + chain + " -p udp --dport 53 -j REDIRECT --to-ports " + port);
        commands.add("#NOCHK# -t nat -A " + chain + " -p tcp --dport 53 -j REDIRECT --to-ports " + port);

        commands.add("#NOCHK# -t nat -A " + preChain + " -i lo -j RETURN");
        commands.add("#NOCHK# -t nat -A " + preChain + " -p udp --dport 53 -j REDIRECT --to-ports " + port);
        commands.add("#NOCHK# -t nat -A " + preChain + " -p tcp --dport 53 -j REDIRECT --to-ports " + port);

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
        config.append("port=").append(G.dnsHijackPort(DEFAULT_PORT)).append('\n');
        config.append("control_socket=").append(new File(dir, SOCKET).getAbsolutePath()).append('\n');
        config.append("pid_file=").append(new File(dir, PID).getAbsolutePath()).append('\n');
        config.append("log_file=").append(new File(dir, QUERY_LOG).getAbsolutePath()).append('\n');
        config.append("fail_open=").append(G.dnsHijackFailOpen() ? "1" : "0").append('\n');
        config.append("strict_mode=").append(G.dnsHijackStrictMode() ? "1" : "0").append('\n');
        config.append("timeout_ms=").append(G.dnsHijackTimeoutMs()).append('\n');

        appendConfigEntries(config, "upstream", G.dnsHijackUpstreams());
        appendConfigEntries(config, "allow_exact", G.dnsHijackAllowExact());
        appendConfigEntries(config, "allow_suffix", G.dnsHijackAllowSuffix());
        appendConfigEntries(config, "block_exact", G.dnsHijackBlockExact());
        appendConfigEntries(config, "block_suffix", G.dnsHijackBlockSuffix());
        appendConfigEntries(config, "allow_regex", G.dnsHijackAllowRegex());
        appendConfigEntries(config, "block_regex", G.dnsHijackBlockRegex());
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

    private static String buildSupervisorScript(File dir, File daemon) {
        String marker = new File(dir, ENABLED_MARKER).getAbsolutePath();
        String config = new File(dir, CONF).getAbsolutePath();
        String pid = new File(dir, PID).getAbsolutePath();
        String log = new File(dir, SUPERVISOR_LOG).getAbsolutePath();

        return "#!/system/bin/sh\n"
                + "DIR=" + shellQuote(dir.getAbsolutePath()) + "\n"
                + "DAEMON=" + shellQuote(daemon.getAbsolutePath()) + "\n"
                + "CONF=" + shellQuote(config) + "\n"
                + "PID=" + shellQuote(pid) + "\n"
                + "MARKER=" + shellQuote(marker) + "\n"
                + "LOG=" + shellQuote(log) + "\n"
                + "is_running() {\n"
                + "  [ -f \"$PID\" ] && kill -0 \"$(cat \"$PID\")\" 2>/dev/null\n"
                + "}\n"
                + "start_daemon() {\n"
                + "  mkdir -p \"$DIR\"\n"
                + "  chmod 700 \"$DIR\" 2>/dev/null || true\n"
                + "  chmod 755 \"$DAEMON\" 2>/dev/null || true\n"
                + "  touch \"$MARKER\"\n"
                + "  if is_running; then exit 0; fi\n"
                + "  ( while [ -f \"$MARKER\" ]; do\n"
                + "      \"$DAEMON\" \"$CONF\" >> \"$LOG\" 2>&1\n"
                + "      sleep 2\n"
                + "    done ) >/dev/null 2>&1 &\n"
                + "  sleep 1\n"
                + "  if is_running; then exit 0; fi\n"
                + "  exit 1\n"
                + "}\n"
                + "stop_daemon() {\n"
                + "  rm -f \"$MARKER\"\n"
                + "  if [ -f \"$PID\" ]; then kill -TERM \"$(cat \"$PID\")\" 2>/dev/null || true; fi\n"
                + "}\n"
                + "case \"$1\" in\n"
                + "  start) start_daemon ;;\n"
                + "  stop) stop_daemon; exit 0 ;;\n"
                + "  restart) stop_daemon; start_daemon ;;\n"
                + "  reload) if is_running; then kill -HUP \"$(cat \"$PID\")\" 2>/dev/null; else start_daemon; fi ;;\n"
                + "  status) if is_running; then echo running; exit 0; else echo stopped; exit 1; fi ;;\n"
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
