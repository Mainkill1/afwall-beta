package dev.ukanth.ufirewall.dns;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Build;
import android.provider.Settings;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import dev.ukanth.ufirewall.Api;
import dev.ukanth.ufirewall.R;
import dev.ukanth.ufirewall.log.Log;
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
    private static final String CONTROL_TOKEN = "afwall_dnsd.control";
    private static final String PID = "afwall_dnsd.pid";
    private static final String SOCKET = "afwall_dnsd.sock";
    private static final String QUERY_LOG = "afwall_dnsd.log";
    private static final String DAEMON_EVENT_LOG = "afwall_dnsd_events.log";
    private static final String SUPERVISOR_LOG = "afwall_dnsd_supervisor.log";
    private static final String SUPERVISOR_PID = "afwall_dnsd_supervisor.pid";
    private static final String RESTART_COUNT = "afwall_dnsd_restart_count";
    private static final String LAST_EXIT = "afwall_dnsd_last_exit";
    private static final String HEARTBEAT = "afwall_dnsd.heartbeat";
    private static final String MARK_STATUS = "afwall_dnsd_mark.status";
    private static final String BOOT_SCRIPT = "afwall_dnsd_boot.sh";
    private static final String BOOT_LOG = "afwall_dnsd_boot.log";
    private static final String CLEANUP_SCRIPT = "afwall_dnsd_cleanup.sh";
    private static final String CLEANUP_LOG = "afwall_dnsd_cleanup.log";
    private static final String MAGISK_MODULE_ID = "afwall_dnsd";
    private static final String MAGISK_MODULE_DIR = "/data/adb/modules/" + MAGISK_MODULE_ID;
    private static final String MAGISK_MODULE_PROP = "module.prop";
    private static final String MAGISK_SERVICE_SCRIPT = "service.sh";
    private static final String MAGISK_UNINSTALL_SCRIPT = "uninstall.sh";
    private static final String MAGISK_MODULE_LOG = "afwall_dnsd_module.log";
    private static final String MAGISK_MODULE_VERSION = "1.3";
    private static final int MAGISK_MODULE_VERSION_CODE = 4;
    private static final String MAGISK_SCRIPT_VERSION = "4";
    private static final String SERVICE_LOG_PREFS = "AFWallDnsServiceLogBridge";
    private static final String[] SERVICE_EVENT_LOGS = new String[] {
            DAEMON_EVENT_LOG,
            SUPERVISOR_LOG,
            BOOT_LOG,
            CLEANUP_LOG
    };
    private static final String CHAIN_V4 = "afwall-dns";
    private static final String CHAIN_V4_PRE = "afwall-dns-pre";
    private static final String CHAIN_V6 = "afwall-dns6";
    private static final String CHAIN_V6_PRE = "afwall-dns6-pre";
    private static final String CHAIN_FILTER = "afwall-dns-out";
    private static final String NFT_TABLE_V4 = "afwall_dns";
    private static final String NFT_TABLE_V6 = "afwall_dns6";
    private static final String NFT_OUTPUT = "output";
    private static final String NFT_PREROUTING = "prerouting";
    private static final String DAEMON_SOCKET_MARK = "0xaf053";
    private static final String PRIVATE_DNS_MODE = "private_dns_mode";
    private static final String PRIVATE_DNS_SPECIFIER = "private_dns_specifier";
    private static final int DEFAULT_PORT = 5354;
    private static final int MAX_SERVICE_LOG_READ = 8192;
    private static final int MAX_SERVICE_LOG_LINES = 30;
    private static final int MAX_SERVICE_LOG_LINE_CHARS = 240;
    private static final int MAX_DIAGNOSTIC_LOG_TAIL = 4096;
    private static final int DNS_QTYPE_A = 1;
    private static final String UNREADABLE_SERVICE_LOG_PREFIX = "unreadable_";
    public static final int RULE_ALLOW_EXACT = 1;
    public static final int RULE_ALLOW_SUFFIX = 2;
    public static final int RULE_BLOCK_EXACT = 3;
    public static final int RULE_BLOCK_SUFFIX = 4;
    public static final int RULE_TEMP_ALLOW = 5;
    public static final int RULE_TEMP_BLOCK = 6;
    public static final int RULE_APP_ALLOW_EXACT = 7;
    public static final int RULE_APP_BLOCK_EXACT = 8;
    public static final int RULE_APP_ALLOW_SUFFIX = 9;
    public static final int RULE_APP_BLOCK_SUFFIX = 10;
    private static final long TEMP_RULE_DURATION_SECONDS = 15L * 60L;

    private DnsHijackManager() {
    }

    public static void appendApplyCommands(Context context, List<String> commands, boolean ipv6) {
        appendPurgeRules(commands, ipv6);
        if (!G.enableDnsHijack()) {
            if (!ipv6) {
                appendStopCommand(context, commands);
                appendRemoveBootPersistenceCommand(commands);
                appendRemoveLifecycleCleanupCommand(commands);
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
            ApplicationErrorLog.add(context, "DNS hijacker enabled; daemon start, daemon filter bypass, and DNS redirect rules queued");
            logRedirectPolicy(context, "DNS redirect policy queued");
            commands.add("#LITERAL# " + buildRepairServiceEventLogFilesCommand(context));
            appendLegacySupervisorStopCommand(context, commands, true);
            commands.add("#LITERAL# " + shellQuote(supervisorPath(context)) + " restart");
            commands.add("#LITERAL# " + buildSupervisorReadinessCheckCommand(context));
            appendBootPersistenceCommand(context, commands);
        } else {
            commands.add("#LITERAL# " + buildSupervisorReadinessCheckCommand(context));
        }
        appendRedirectRules(context, commands, ipv6);
        commands.add("#LITERAL# " + buildNftFallbackRestoreCommand(context, ipv6));
        commands.add("#LITERAL# " + buildRedirectInstallVerificationCommand(context, ipv6));
    }

    public static void appendPurgeCommands(Context context, List<String> commands, boolean ipv6) {
        appendPurgeRules(commands, ipv6);
        if (!ipv6) {
            commands.add("#LITERAL# " + buildNftPurgeCommand());
        }
        if (!ipv6) {
            appendStopCommand(context, commands);
            appendRemoveBootPersistenceCommand(commands);
            appendRemoveLifecycleCleanupCommand(commands);
        }
    }

    public static void applyDnsProtectionPreference(Context context, boolean enabled,
                                                    RootCommand.Callback callback) {
        if (context == null) {
            return;
        }
        if (enabled) {
            if (!prepareDaemon(context)) {
                failSupervisorAction(context, callback,
                        "DNS protection enable requested but daemon files could not be prepared");
                return;
            }
            runLifecycleCommands(context,
                    buildRootRepairCommands(context),
                    "DNS protection enable queued: daemon start, daemon filter bypass, redirect reinstall, boot persistence sync",
                    "DNS protection enable completed",
                    "DNS protection enable failed",
                    callback);
            return;
        }

        if (clearEnableMarkerBeforeRoot(context, "DNS protection disable")) {
            requestDaemonFailOpen(context, "DNS protection disable");
        }
        runLifecycleCommands(context,
                buildRootRemovalCommands(context),
                "DNS protection disable queued: redirect teardown, daemon stop, boot persistence removal",
                "DNS protection disable completed",
                "DNS protection disable failed",
                callback);
    }

    public static void emergencyCleanupDnsProtection(Context context,
                                                     RootCommand.Callback callback) {
        if (context == null) {
            return;
        }
        if (clearEnableMarkerBeforeRoot(context, "DNS emergency cleanup")) {
            requestDaemonFailOpen(context, "DNS emergency cleanup");
        }
        runLifecycleCommands(context,
                buildRootEmergencyCleanupCommands(context),
                "DNS emergency cleanup queued: direct redirect teardown, daemon stop, and Magisk module removal",
                "DNS emergency cleanup completed",
                "DNS emergency cleanup failed",
                callback);
    }

    public static void updateBootPersistence(Context context, RootCommand.Callback callback) {
        if (context == null) {
            return;
        }
        List<String> commands = new ArrayList<>();
        if (G.dnsHijackBootPersistence() && G.enableDnsHijack()) {
            if (!prepareDaemon(context)) {
                failSupervisorAction(context, callback,
                        "DNS boot persistence enable requested but daemon files could not be prepared");
                return;
            }
            commands.add(buildInstallBootPersistenceCommand(workDir(context), true));
            runLifecycleCommands(context,
                    commands,
                    "DNS boot persistence install queued",
                    "DNS boot persistence install completed",
                    "DNS boot persistence install failed",
                    callback);
            return;
        }

        commands.add(buildRemoveBootPersistenceCommand());
        runLifecycleCommands(context,
                commands,
                "DNS boot persistence removal queued",
                "DNS boot persistence removal completed",
                "DNS boot persistence removal failed",
                callback);
    }

    public static void requestReload(Context context) {
        if (context == null) {
            return;
        }
        if (prepareDaemon(context)) {
            String response = queryControl(context, "reload");
            syncServiceLogsToAppLog(context);
            if (response.startsWith("ok reload")) {
                ApplicationErrorLog.add(context, "DNS daemon control reload completed: "
                        + compactControlResponse(response));
                restoreRedirectsAfterReload(context);
                return;
            }
            ApplicationErrorLog.add(context,
                    "DNS daemon control reload unavailable; falling back to supervisor reload: "
                            + compactControlResponse(response));
        }
        runSupervisorAction(context, "reload", null);
    }

    private static void restoreRedirectsAfterReload(Context context) {
        if (context == null || !G.enableDnsHijack()) {
            return;
        }
        List<String> commands = new ArrayList<>();
        commands.add(buildRepairServiceEventLogFilesCommand(context));
        logRedirectPolicy(context, "DNS redirect policy reload restore queued");
        appendRootRedirectRepairCommands(context, commands, false);
        if (G.enableIPv6()) {
            appendRootRedirectRepairCommands(context, commands, true);
        } else {
            appendDirectPurgeRules(context, commands, true);
            commands.add(buildNftFamilyPurgeCommand(true));
        }
        ApplicationErrorLog.add(context, "DNS redirect reload restore queued");
        new RootCommand()
                .setLogging(true)
                .setReopenShell(true)
                .setFailureToast(R.string.error_apply)
                .setCallback(new RootCommand.Callback() {
                    @Override
                    public void cbFunc(RootCommand state) {
                        if (state.exitCode == 0) {
                            ApplicationErrorLog.add(context, "DNS redirect reload restore completed");
                        } else {
                            ApplicationErrorLog.add(context,
                                    "DNS redirect reload restore failed" + rootFailureSuffix(state));
                        }
                        syncServiceLogsToAppLog(context);
                    }
                })
                .run(context.getApplicationContext(), commands);
    }

    public static String validateDnsConfiguration(Context context) {
        if (context == null) {
            return "validation unavailable: missing context\n";
        }
        String response = queryControl(context, "validate");
        syncServiceLogsToAppLog(context);
        if (isDnsValidationRejected(response)) {
            ApplicationErrorLog.add(context, "DNS daemon validation rejected config: "
                    + compactControlResponse(response));
        } else if (response.startsWith("validate=1")) {
            ApplicationErrorLog.add(context, "DNS daemon validation accepted config: "
                    + compactControlResponse(response));
        } else {
            ApplicationErrorLog.add(context, "DNS daemon validation unavailable: "
                    + compactControlResponse(response));
        }
        return response;
    }

    public static boolean isDnsValidationRejected(String response) {
        if (response == null) {
            return false;
        }
        return response.startsWith("validate=0") || response.contains("\nvalidate=0")
                || response.contains("status=config_rejected")
                || response.contains("status=allocation_failed");
    }

    public static String runDaemonMaintenanceAction(Context context, String action) {
        if (context == null) {
            return "maintenance unavailable: missing context\n";
        }
        String command = normalizeDaemonMaintenanceAction(action);
        if (command == null) {
            ApplicationErrorLog.add(context, "DNS daemon maintenance action rejected: " + action);
            return "maintenance unavailable: invalid action\n";
        }
        String response = queryControl(context, command);
        syncServiceLogsToAppLog(context);
        if (response.startsWith("ok ")) {
            ApplicationErrorLog.add(context, "DNS daemon maintenance completed: "
                    + compactControlResponse(response));
        } else {
            ApplicationErrorLog.add(context, "DNS daemon maintenance failed: "
                    + compactControlResponse(response));
        }
        return response;
    }

    public static String runControlAuthSelfTest(Context context) {
        if (context == null) {
            return "control_auth_self_test=0\nreason=missing_context\n";
        }
        StringBuilder out = new StringBuilder();
        File socketFile = new File(workDir(context), SOCKET);
        out.append("control_auth_self_test=1\n");
        out.append("socket_present=").append(socketFile.exists()).append('\n');
        out.append("app_uid=").append(context.getApplicationInfo().uid).append('\n');
        String validate = queryControl(context, "validate");
        Map<String, String> validateValues = parseKeyValueLines(validate);
        out.append("authorized_control=");
        if ("1".equals(validateValues.get("validate"))) {
            out.append("ok\n");
        } else {
            out.append("failed\n");
        }
        appendSelfTestValue(out, validateValues, "control_socket_configured");
        appendSelfTestValue(out, validateValues, "control_socket_uid");
        appendSelfTestValue(out, validateValues, "control_auth_configured");
        appendSelfTestValue(out, validateValues, "control_peer_uid_enforced");
        String badTokenResponse = queryControl(context, "status", buildInvalidControlToken(context));
        boolean badTokenRejected = badTokenResponse.trim().startsWith("error unauthorized");
        out.append("bad_token_rejected=").append(badTokenRejected ? "1" : "0").append('\n');
        if (!badTokenRejected) {
            out.append("bad_token_response=")
                    .append(compactControlResponse(badTokenResponse)).append('\n');
        }
        syncServiceLogsToAppLog(context);
        if (badTokenRejected
                && "1".equals(validateValues.get("control_auth_configured"))
                && "1".equals(validateValues.get("control_peer_uid_enforced"))) {
            ApplicationErrorLog.add(context, "DNS control auth self-test passed");
        } else {
            ApplicationErrorLog.add(context, "DNS control auth self-test failed: "
                    + compactControlResponse(out.toString()));
        }
        return out.toString();
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
        commands.add(buildRepairServiceEventLogFilesCommand(context));
        commands.add(shellQuote(supervisor.getAbsolutePath()) + " " + safeAction);
        ApplicationErrorLog.add(context, "DNS hijacker supervisor action queued: " + safeAction);
        new RootCommand()
                .setLogging(true)
                .setReopenShell(true)
                .setFailureToast(R.string.error_apply)
                .setCallback(new RootCommand.Callback() {
                    @Override
                    public void cbFunc(RootCommand state) {
                        syncServiceLogsToAppLog(context);
                        if (callback != null) {
                            callback.cbFunc(state);
                        }
                    }
                })
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
        ApplicationErrorLog.add(context, "DNS hijacker repair queued: daemon start, daemon filter bypass, and DNS redirect reinstall");
        new RootCommand()
                .setLogging(true)
                .setReopenShell(true)
                .setFailureToast(R.string.error_apply)
                .setCallback(new RootCommand.Callback() {
                    @Override
                    public void cbFunc(RootCommand state) {
                        syncServiceLogsToAppLog(context);
                        if (callback != null) {
                            callback.cbFunc(state);
                        }
                    }
                })
                .run(context.getApplicationContext(), commands);
    }

    public static void pauseDnsProtection(Context context, RootCommand.Callback callback) {
        if (context == null) {
            return;
        }
        boolean previousEnabled = G.enableDnsHijack();
        G.enableDnsHijack(false);
        Api.setRulesUpToDate(false);
        boolean localStopArmed = clearEnableMarkerBeforeRoot(context, "DNS protection pause");
        if (localStopArmed) {
            requestDaemonFailOpen(context, "DNS protection pause");
        }
        List<String> commands = buildRootRemovalCommands(context);
        ApplicationErrorLog.add(context, "DNS protection pause queued: redirect teardown and daemon stop");
        new RootCommand()
                .setLogging(true)
                .setReopenShell(true)
                .setFailureToast(R.string.error_apply)
                .setCallback(new RootCommand.Callback() {
                    @Override
                    public void cbFunc(RootCommand state) {
                        if (state.exitCode != 0 && !localStopArmed) {
                            G.enableDnsHijack(previousEnabled);
                            Api.setRulesUpToDate(false);
                            ApplicationErrorLog.add(context, "DNS protection pause failed; restored previous enabled setting");
                        } else if (state.exitCode != 0) {
                            ApplicationErrorLog.add(context,
                                    "DNS protection pause root cleanup failed after enable marker was cleared; leaving DNS protection disabled for fail-open recovery");
                        }
                        syncServiceLogsToAppLog(context);
                        if (callback != null) {
                            callback.cbFunc(state);
                        }
                    }
                })
                .run(context.getApplicationContext(), commands);
    }

    public static void resumeDnsProtection(Context context, RootCommand.Callback callback) {
        if (context == null) {
            return;
        }
        boolean previousEnabled = G.enableDnsHijack();
        G.enableDnsHijack(true);
        Api.setRulesUpToDate(false);
        if (!prepareDaemon(context)) {
            G.enableDnsHijack(previousEnabled);
            failSupervisorAction(context, callback, "DNS protection resume requested but daemon files could not be prepared");
            return;
        }

        List<String> commands = buildRootRepairCommands(context);
        ApplicationErrorLog.add(context, "DNS protection resume queued: daemon start, daemon filter bypass, and DNS redirect reinstall");
        new RootCommand()
                .setLogging(true)
                .setReopenShell(true)
                .setFailureToast(R.string.error_apply)
                .setCallback(new RootCommand.Callback() {
                    @Override
                    public void cbFunc(RootCommand state) {
                        if (state.exitCode != 0) {
                            G.enableDnsHijack(previousEnabled);
                            Api.setRulesUpToDate(false);
                            ApplicationErrorLog.add(context, "DNS protection resume failed; restored previous enabled setting");
                        }
                        syncServiceLogsToAppLog(context);
                        if (callback != null) {
                            callback.cbFunc(state);
                        }
                    }
                })
                .run(context.getApplicationContext(), commands);
    }

    public static String collectLocalDiagnostics(Context context) {
        syncServiceLogsToAppLog(context);
        StringBuilder out = new StringBuilder();
        File dir = workDir(context);
        File daemon = new File(dir, DAEMON_NAME);
        File supervisor = new File(dir, SUPERVISOR);
        File config = new File(dir, CONF);
        File controlToken = new File(dir, CONTROL_TOKEN);
        File pid = new File(dir, PID);
        File socket = new File(dir, SOCKET);
        File queryLog = new File(dir, QUERY_LOG);
        File daemonEventLog = new File(dir, DAEMON_EVENT_LOG);
        File supervisorLog = new File(dir, SUPERVISOR_LOG);
        File supervisorPid = new File(dir, SUPERVISOR_PID);
        File restartCount = new File(dir, RESTART_COUNT);
        File lastExit = new File(dir, LAST_EXIT);
        File heartbeat = new File(dir, HEARTBEAT);
        File markStatus = new File(dir, MARK_STATUS);
        File bootScript = new File(dir, BOOT_SCRIPT);
        File bootLog = new File(dir, BOOT_LOG);
        File cleanupScript = new File(dir, CLEANUP_SCRIPT);
        File cleanupLog = new File(dir, CLEANUP_LOG);
        File moduleProp = new File(dir, MAGISK_MODULE_PROP);
        File moduleService = new File(dir, MAGISK_SERVICE_SCRIPT);
        File moduleUninstall = new File(dir, MAGISK_UNINSTALL_SCRIPT);

        out.append("enabled_pref=").append(G.enableDnsHijack()).append('\n');
        out.append("work_dir_storage=").append(workDirStorageLabel(context)).append('\n');
        out.append("active_profile=").append(G.activeDnsHijackPolicyProfile()).append('\n');
        out.append("profile_dns_overrides_enabled=").append(G.dnsHijackUseProfilePolicy()).append('\n');
        out.append("active_profile_dns_override_saved=")
                .append(G.activeDnsHijackProfilePolicySaved()).append('\n');
        out.append("effective_dns_policy_source=").append(effectiveDnsPolicySource()).append('\n');
        out.append("blocklist_storage=").append(G.dnsHijackBlocklistDirectoryName("dnsd_blocklists"))
                .append('\n');
        out.append("boot_persistence_pref=").append(G.dnsHijackBootPersistence()).append('\n');
        out.append("expected_magisk_script_version=").append(MAGISK_SCRIPT_VERSION).append('\n');
        out.append("expected_magisk_module_version=").append(MAGISK_MODULE_VERSION).append('\n');
        out.append("boot_restore_ipv6_enabled=").append(G.enableIPv6()).append('\n');
        out.append("port=").append(G.dnsHijackPort(DEFAULT_PORT)).append('\n');
        appendManualRecoveryNotes(out);
        out.append("\n[android dns compatibility]\n");
        appendAndroidDnsCompatibility(context, out);
        out.append('\n');
        out.append("fail_open=").append(G.dnsHijackFailOpen()).append('\n');
        out.append("strict_mode=").append(G.dnsHijackStrictMode()).append('\n');
        out.append("safe_search=").append(G.dnsHijackSafeSearch()).append('\n');
        out.append("dnssec_request=").append(G.dnsHijackDnssecRequest()).append('\n');
        out.append("dnssec_auth_required=").append(G.dnsHijackDnssecAuthRequired()).append('\n');
        out.append("timeout_ms=").append(G.dnsHijackTimeoutMs()).append('\n');
        out.append("cache_size=").append(G.dnsHijackCacheSize()).append('\n');
        out.append("stale_cache_seconds=").append(G.dnsHijackStaleCacheSeconds()).append('\n');
        out.append("persist_cache=").append(G.dnsHijackPersistCache()).append('\n');
        out.append("query_logging=").append(G.dnsHijackQueryLogging()).append('\n');
        out.append("persist_query_logs=").append(G.dnsHijackPersistQueryLogs()).append('\n');
        out.append("bootstrap_upstream_entries=").append(countLines(G.dnsHijackBootstrapUpstreams())).append('\n');
        out.append("split_upstream_entries=").append(countLines(G.dnsHijackSplitUpstreams())).append('\n');
        out.append("capture_uid_entries=").append(parseUidList(G.dnsHijackCaptureUids()).size()).append('\n');
        out.append("bypass_uid_entries=").append(parseUidList(G.dnsHijackBypassUids()).size()).append('\n');
        out.append("capture_interface_entries=")
                .append(parseInterfaceList(G.dnsHijackCaptureInterfaces()).size()).append('\n');
        out.append("bypass_interface_entries=")
                .append(parseInterfaceList(G.dnsHijackBypassInterfaces()).size()).append('\n');
        out.append("nft_table_v4=").append(NFT_TABLE_V4).append('\n');
        out.append("nft_table_v6=").append(NFT_TABLE_V6).append('\n');
        out.append("scheduled_blocklist_updates=").append(G.dnsHijackScheduledBlocklistUpdates()).append('\n');
        out.append("blocklist_update_interval_hours=")
                .append(G.dnsHijackBlocklistUpdateIntervalHours()).append('\n');
        out.append("app_allow_exact_entries=").append(countLines(G.dnsHijackAppAllowExact())).append('\n');
        out.append("app_block_exact_entries=").append(countLines(G.dnsHijackAppBlockExact())).append('\n');
        out.append("app_allow_suffix_entries=").append(countLines(G.dnsHijackAppAllowSuffix())).append('\n');
        out.append("app_block_suffix_entries=").append(countLines(G.dnsHijackAppBlockSuffix())).append('\n');
        out.append("network_allow_entries=").append(countLines(G.dnsHijackNetworkAllow())).append('\n');
        out.append("network_block_entries=").append(countLines(G.dnsHijackNetworkBlock())).append('\n');
        out.append("temporary_allow_entries=").append(countLines(G.dnsHijackTempAllow())).append('\n');
        out.append("temporary_block_entries=").append(countLines(G.dnsHijackTempBlock())).append('\n');
        out.append("\n[blocklists]\n");
        out.append(DnsBlocklistManager.getSummary(context)).append('\n');
        appendFileInfo(out, "work_dir", dir);
        appendFileInfo(out, "daemon", daemon);
        appendFileInfo(out, "supervisor", supervisor);
        appendFileInfo(out, "config", config);
        appendFileInfo(out, "control_token", controlToken);
        appendFileInfo(out, "pid", pid);
        appendFileInfo(out, "control_socket", socket);
        appendFileInfo(out, "query_log", queryLog);
        appendFileInfo(out, "daemon_event_log", daemonEventLog);
        appendFileInfo(out, "supervisor_log", supervisorLog);
        appendFileInfo(out, "supervisor_pid", supervisorPid);
        appendFileInfo(out, "restart_count", restartCount);
        appendFileInfo(out, "last_exit", lastExit);
        appendFileInfo(out, "heartbeat", heartbeat);
        appendFileInfo(out, "mark_status", markStatus);
        appendFileInfo(out, "boot_script", bootScript);
        appendFileInfo(out, "boot_log", bootLog);
        appendFileInfo(out, "cleanup_script", cleanupScript);
        appendFileInfo(out, "cleanup_log", cleanupLog);
        appendFileInfo(out, "magisk_module_prop", moduleProp);
        appendFileInfo(out, "magisk_service_script", moduleService);
        appendFileInfo(out, "magisk_uninstall_script", moduleUninstall);

        out.append("\n[supervisor metadata]\n");
        appendSmallFileValue(out, "watchdog_pid", supervisorPid);
        appendSmallFileValue(out, "restart_count", restartCount);
        appendSmallFileValue(out, "last_exit", lastExit);
        appendSmallFileValue(out, "heartbeat", heartbeat);
        appendSmallFileValue(out, "mark_status", markStatus);

        out.append("\n[service event log bridge]\n");
        appendServiceLogBridgeStatus(context, out, "daemon", daemonEventLog);
        appendServiceLogBridgeStatus(context, out, "supervisor", supervisorLog);
        appendServiceLogBridgeStatus(context, out, "boot", bootLog);
        appendServiceLogBridgeStatus(context, out, "cleanup", cleanupLog);
        out.append("\n[recent service events]\n");
        appendTailFileValue(out, "daemon_recent", daemonEventLog, MAX_DIAGNOSTIC_LOG_TAIL);
        appendTailFileValue(out, "supervisor_recent", supervisorLog, MAX_DIAGNOSTIC_LOG_TAIL);
        appendTailFileValue(out, "boot_recent", bootLog, MAX_DIAGNOSTIC_LOG_TAIL);
        appendTailFileValue(out, "cleanup_recent", cleanupLog, MAX_DIAGNOSTIC_LOG_TAIL);

        out.append("\n[control status]\n");
        out.append(queryControl(context, "status"));
        out.append("\n[control health]\n");
        out.append(queryControl(context, "health"));
        out.append("\n[control validate]\n");
        out.append(queryControl(context, "validate"));
        out.append("\n[recent queries]\n");
        String logs = queryControl(context, "logs");
        out.append(logs.trim().isEmpty() ? "no daemon query logs reported\n" : logs);
        return out.toString();
    }

    public static List<QueryEntry> getRecentQueries(Context context) {
        return parseQueryEntries(queryControl(context, "logs"));
    }

    private static void appendManualRecoveryNotes(StringBuilder out) {
        if (out == null) {
            return;
        }
        out.append("\n[manual recovery]\n");
        out.append("module_id=").append(MAGISK_MODULE_ID).append('\n');
        out.append("module_dir=").append(MAGISK_MODULE_DIR).append('\n');
        out.append("module_log=/data/local/tmp/").append(MAGISK_MODULE_LOG).append('\n');
        out.append("root_shell_notes=If AFWall cannot open, disable the module from Magisk or recovery, then reboot.\n");
        out.append("root_shell_commands=\n");
        out.append("  MOD=").append(MAGISK_MODULE_DIR).append('\n');
        out.append("  [ -x \"$MOD/").append(MAGISK_UNINSTALL_SCRIPT)
                .append("\" ] && \"$MOD/").append(MAGISK_UNINSTALL_SCRIPT).append("\"\n");
        out.append("  touch \"$MOD/disable\" \"$MOD/remove\" 2>/dev/null || true\n");
        out.append("  iptables -D OUTPUT -m mark --mark ").append(DAEMON_SOCKET_MARK)
                .append(" -j ACCEPT 2>/dev/null || true\n");
        out.append("  ip6tables -D OUTPUT -m mark --mark ").append(DAEMON_SOCKET_MARK)
                .append(" -j ACCEPT 2>/dev/null || true\n");
        out.append("  iptables -D OUTPUT -j ").append(CHAIN_FILTER).append(" 2>/dev/null || true\n");
        out.append("  iptables -F ").append(CHAIN_FILTER).append(" 2>/dev/null || true\n");
        out.append("  iptables -X ").append(CHAIN_FILTER).append(" 2>/dev/null || true\n");
        out.append("  ip6tables -D OUTPUT -j ").append(CHAIN_FILTER).append(" 2>/dev/null || true\n");
        out.append("  ip6tables -F ").append(CHAIN_FILTER).append(" 2>/dev/null || true\n");
        out.append("  ip6tables -X ").append(CHAIN_FILTER).append(" 2>/dev/null || true\n");
        appendManualRecoveryFamilyCommands(out, "iptables", CHAIN_V4, CHAIN_V4_PRE);
        appendManualRecoveryFamilyCommands(out, "ip6tables", CHAIN_V6, CHAIN_V6_PRE);
        out.append("  nft delete table ip ").append(NFT_TABLE_V4).append(" 2>/dev/null || true\n");
        out.append("  nft delete table ip6 ").append(NFT_TABLE_V6).append(" 2>/dev/null || true\n");
        out.append("  reboot\n");
    }

    private static void appendManualRecoveryFamilyCommands(StringBuilder out, String tool,
                                                           String chain, String preChain) {
        out.append("  ").append(tool).append(" -t nat -D OUTPUT -p udp --dport 53 -j ")
                .append(chain).append(" 2>/dev/null || true\n");
        out.append("  ").append(tool).append(" -t nat -D OUTPUT -p tcp --dport 53 -j ")
                .append(chain).append(" 2>/dev/null || true\n");
        out.append("  ").append(tool).append(" -t nat -D PREROUTING -p udp --dport 53 -j ")
                .append(preChain).append(" 2>/dev/null || true\n");
        out.append("  ").append(tool).append(" -t nat -D PREROUTING -p tcp --dport 53 -j ")
                .append(preChain).append(" 2>/dev/null || true\n");
        out.append("  ").append(tool).append(" -t nat -F ").append(chain)
                .append(" 2>/dev/null || true\n");
        out.append("  ").append(tool).append(" -t nat -F ").append(preChain)
                .append(" 2>/dev/null || true\n");
        out.append("  ").append(tool).append(" -t nat -X ").append(chain)
                .append(" 2>/dev/null || true\n");
        out.append("  ").append(tool).append(" -t nat -X ").append(preChain)
                .append(" 2>/dev/null || true\n");
    }

    public static String getRecentServiceEvents(Context context) {
        if (context == null) {
            return "";
        }
        syncServiceLogsToAppLog(context);
        File dir = workDir(context);
        StringBuilder out = new StringBuilder();
        appendRecentServiceEvents(out, "daemon", new File(dir, DAEMON_EVENT_LOG));
        appendRecentServiceEvents(out, "supervisor", new File(dir, SUPERVISOR_LOG));
        appendRecentServiceEvents(out, "boot", new File(dir, BOOT_LOG));
        appendRecentServiceEvents(out, "cleanup", new File(dir, CLEANUP_LOG));
        return out.toString().trim();
    }

    public static DnsDashboardSnapshot getDashboardSnapshot(Context context) {
        syncServiceLogsToAppLog(context);
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
        long queriesToday = parseLong(firstValue(statusValues, healthValues, "queries_today"), queries);
        long blockedToday = parseLong(firstValue(statusValues, healthValues, "blocked_today"), blocked);
        long allowedToday = parseLong(firstValue(statusValues, healthValues, "allowed_today"), 0L);
        long reloads = parseLong(firstValue(statusValues, healthValues, "reloads"), 0L);
        long reloadFailures = parseLong(firstValue(statusValues, healthValues, "reload_failures"), 0L);
        long uptime = parseLong(firstValue(statusValues, healthValues, "uptime"), 0L);
        long cacheSize = parseLong(firstValue(statusValues, healthValues, "cache_size"), 0L);
        long cacheEntries = parseLong(firstValue(statusValues, healthValues, "cache_entries"), 0L);
        long cacheHits = parseLong(firstValue(statusValues, healthValues, "cache_hits"), 0L);
        long cacheMisses = parseLong(firstValue(statusValues, healthValues, "cache_misses"), 0L);
        long cacheHitRatePpm = parseLong(firstValue(statusValues, healthValues, "cache_hit_rate_ppm"), -1L);
        long cacheStaleHits = parseLong(firstValue(statusValues, healthValues, "cache_stale_hits"), 0L);
        long avgLatency = parseLong(firstValue(statusValues, healthValues, "avg_latency_ms"), -1L);
        long maxLatency = parseLong(firstValue(statusValues, healthValues, "max_latency_ms"), -1L);
        long upstreamAvgLatency = parseLong(firstValue(statusValues, healthValues,
                "upstream_avg_latency_ms"), -1L);
        long upstreamRequests = parseLong(firstValue(statusValues, healthValues,
                "upstream_requests"), 0L);
        long upstreamSuccesses = parseLong(firstValue(statusValues, healthValues,
                "upstream_successes"), 0L);
        long upstreamFailures = parseLong(firstValue(statusValues, healthValues,
                "upstream_failures"), 0L);
        long upstreamBackoffActive = parseLong(firstValue(statusValues, healthValues,
                "upstream_backoff_active"), 0L);
        long compiledUpstreams = parseLong(firstValue(statusValues, healthValues,
                "compiled_upstream_addresses"), 0L);
        long reusableUdpSockets = parseLong(firstValue(statusValues, healthValues,
                "reusable_udp_upstream_sockets"), 0L);
        long socketMarkSupported = parseLong(firstValue(statusValues, healthValues,
                "socket_mark_supported"), -1L);
        long socketMarkFailures = parseLong(firstValue(statusValues, healthValues,
                "socket_mark_failures"), 0L);
        long failOpenControlSupported = parseLong(firstValue(statusValues, healthValues,
                "fail_open_control_supported"), -1L);
        long cleanupIptablesSafe = parseLong(firstValue(statusValues, healthValues,
                "cleanup_iptables_safe"), -1L);
        long cleanupIp6tablesSafe = parseLong(firstValue(statusValues, healthValues,
                "cleanup_ip6tables_safe"), -1L);
        long memoryRssKb = parseLong(firstValue(statusValues, healthValues, "memory_rss_kb"), -1L);
        long memoryHwmKb = parseLong(firstValue(statusValues, healthValues, "memory_hwm_kb"), -1L);
        long cpuTotalMs = parseLong(firstValue(statusValues, healthValues, "cpu_total_ms"), -1L);
        long logRingEntries = parseLong(firstValue(statusValues, healthValues,
                "log_ring_entries"), 0L);
        long logUnflushedEntries = parseLong(firstValue(statusValues, healthValues,
                "log_unflushed_entries"), 0L);
        long ruleCount = parseLong(firstValue(healthValues, statusValues, "rules_total"), -1L);
        if (ruleCount < 0L) {
            ruleCount = sumDashboardRuleCounts(statusValues, healthValues);
        }
        boolean ipv6Expected = G.enableIPv6();
        boolean udpListener = "1".equals(firstValue(statusValues, healthValues, "udp_listener"));
        boolean tcpListener = "1".equals(firstValue(statusValues, healthValues, "tcp_listener"));
        boolean udpListenerV4 = listenerFamilyReady(statusValues, healthValues,
                "udp_listener_v4", "udp_listener");
        boolean udpListenerV6 = listenerFamilyReady(statusValues, healthValues,
                "udp_listener_v6", "udp_listener");
        boolean tcpListenerV4 = listenerFamilyReady(statusValues, healthValues,
                "tcp_listener_v4", "tcp_listener");
        boolean tcpListenerV6 = listenerFamilyReady(statusValues, healthValues,
                "tcp_listener_v6", "tcp_listener");
        boolean controlListener = "1".equals(firstValue(statusValues, healthValues, "control_listener"));
        boolean privateDnsBypass = androidPrivateDnsMayBypass(context);
        boolean rootUidBypass = false;
        long upstreamLatency = parseLong(firstValue(healthValues, statusValues, "upstream_probe_ms"), -1L);
        String upstreamProbe = firstValue(healthValues, statusValues, "upstream_probe");
        boolean listenersReady = controlListener && udpListener && tcpListener
                && udpListenerV4 && tcpListenerV4
                && (!ipv6Expected || (udpListenerV6 && tcpListenerV6));
        boolean upstreamHealthy = upstreamLatency >= 0L && "ok".equalsIgnoreCase(upstreamProbe);
        String powerStatus = androidPowerDashboardLine(context);
        String restartCount = readSmallFileValue(new File(workDir(context), RESTART_COUNT), "0");
        String profile = G.activeDnsHijackPolicyProfile();
        if (profile == null || profile.trim().isEmpty()) {
            profile = "global";
        }
        String profilePolicyLabel = " | Policy: " + effectiveDnsPolicySource();
        String blockPercent = queriesToday <= 0L
                ? "0%"
                : String.format(Locale.US, "%.1f%%", (blockedToday * 100.0d) / queriesToday);
        String protection;
        if (!enabled) {
            protection = "DNS protection disabled";
        } else if (running) {
            protection = "DNS protection active";
        } else {
            protection = "DNS protection enabled, daemon unavailable";
        }

        String statusLine = protection + " | " + queriesToday + " queries today | "
                + blockPercent + " blocked";
        if (enabled && privateDnsBypass) {
            statusLine += " | Private DNS may bypass";
        }
        String blocklistUpdated = blocklistValues.containsKey("updated")
                ? blocklistValues.get("updated")
                : "never";
        String upstream = upstreamProbe == null || upstreamProbe.trim().isEmpty()
                ? "unknown"
                : upstreamProbe;
        if (upstreamLatency >= 0L) {
            upstream += " " + upstreamLatency + "ms";
        }
        String cacheLine = cacheSize <= 0L
                ? "Cache: disabled"
                : "Cache: " + cacheEntries + "/" + cacheSize
                + " | Hit rate: " + cacheHitRate(cacheHitRatePpm, cacheHits, cacheMisses)
                + " | Stale hits: " + cacheStaleHits;
        String latencyLine = "Latency: avg " + formatMillis(avgLatency)
                + " | upstream avg " + formatMillis(upstreamAvgLatency)
                + " | max " + formatMillis(maxLatency);
        String upstreamLine = "Upstream: " + upstream
                + " | Requests: " + upstreamSuccesses + "/" + upstreamRequests
                + " ok | Failures: " + upstreamFailures
                + " | Backoff: " + upstreamBackoffActive
                + "\nResolvers: compiled " + compiledUpstreams
                + " | UDP sockets: " + reusableUdpSockets
                + " | " + upstreamRuntimeSummary(statusValues, healthValues);
        String systemLine = "System: uptime " + formatDuration(uptime)
                + " | RSS " + formatKilobytes(memoryRssKb)
                + " | HWM " + formatKilobytes(memoryHwmKb)
                + " | CPU " + formatMillis(cpuTotalMs);
        String rulesLine = "Rules: " + ruleCount
                + " | Log ring: " + logRingEntries
                + " | Pending log writes: " + logUnflushedEntries;
        String routingLine = "DNS routing: daemon mark " + DAEMON_SOCKET_MARK
                + " " + daemonMarkSupportLabel(socketMarkSupported)
                + " | Mark failures: " + socketMarkFailures;
        boolean failOpenCleanupArmed = failOpenControlSupported == 1L
                && cleanupIptablesSafe == 1L
                && (!ipv6Expected || cleanupIp6tablesSafe == 1L);
        String failOpenLine = "Fail-open cleanup: "
                + (failOpenCleanupArmed ? "armed" : "degraded")
                + " | control " + yesNoUnknown(failOpenControlSupported)
                + " | IPv4 tool " + yesNoUnknown(cleanupIptablesSafe)
                + " | IPv6 tool " + listenerFamilyLabel(cleanupIp6tablesSafe == 1L, ipv6Expected);
        String routingScopeLine = preroutingRedirectExpected()
                ? "DNS scope: local and forwarded port-53 capture"
                : "DNS scope: UID-scoped app-owned port-53 sockets; Android system resolver traffic may use a system UID";
        String details = "Daemon: " + (running ? "running" : "stopped")
                + " | Redirect setting: " + (enabled ? "enabled" : "disabled")
                + " | Profile: " + profile
                + profilePolicyLabel
                + privateDnsDashboardLine(context)
                + "\n" + routingLine
                + "\n" + failOpenLine
                + "\n" + routingScopeLine
                + "\nBlocklist updated: " + blocklistUpdated
                + "\nToday: " + allowedToday + " allowed | " + blockedToday + " blocked"
                + "\nTotal: " + queries + " queries | Restarts: " + restartCount
                + " | Reloads: " + reloads
                + " | Reload failures: " + reloadFailures
                + "\n" + cacheLine
                + "\n" + latencyLine
                + "\n" + upstreamLine
                + "\n" + systemLine
                + "\n" + powerStatus
                + "\n" + rulesLine
                + "\nListeners: UDP v4 " + listenerLabel(udpListenerV4)
                + " | UDP v6 " + listenerFamilyLabel(udpListenerV6, ipv6Expected)
                + " | TCP v4 " + listenerLabel(tcpListenerV4)
                + " | TCP v6 " + listenerFamilyLabel(tcpListenerV6, ipv6Expected)
                + " | Control " + listenerLabel(controlListener);
        return new DnsDashboardSnapshot(statusLine, details, enabled, running,
                listenersReady, upstreamHealthy, privateDnsBypass, rootUidBypass, powerStatus);
    }

    private static String effectiveDnsPolicySource() {
        if (!G.dnsHijackUseProfilePolicy()) {
            return "global";
        }
        return G.activeDnsHijackProfilePolicySaved()
                ? "active_profile_override"
                : "global_fallback_no_active_profile_override";
    }

    public static boolean androidPrivateDnsMayBypass(Context context) {
        return privateDnsModeCanBypass(readAndroidPrivateDnsMode(context));
    }

    public static String androidPrivateDnsMode(Context context) {
        return readAndroidPrivateDnsMode(context);
    }

    public static String androidPrivateDnsSpecifier(Context context) {
        return readAndroidPrivateDnsSpecifier(context);
    }

    public static String androidPrivateDnsWarning(Context context) {
        String mode = readAndroidPrivateDnsMode(context);
        if (!privateDnsModeCanBypass(mode)) {
            return null;
        }
        String specifier = readAndroidPrivateDnsSpecifier(context);
        String provider = specifier.isEmpty() ? "" : " (" + specifier + ")";
        return "Android Private DNS is " + mode + provider
                + ". Root DNS capture redirects UDP/TCP port 53, so Private DNS can bypass it.";
    }

    public static void syncServiceLogsToAppLog(Context context) {
        if (context == null) {
            return;
        }
        try {
            File dir = workDir(context);
            SharedPreferences prefs = context.getApplicationContext()
                    .getSharedPreferences(SERVICE_LOG_PREFS, Context.MODE_PRIVATE);
            syncServiceLogFile(context, prefs, new File(dir, DAEMON_EVENT_LOG), "daemon");
            syncServiceLogFile(context, prefs, new File(dir, SUPERVISOR_LOG), "supervisor");
            syncServiceLogFile(context, prefs, new File(dir, BOOT_LOG), "boot");
            syncServiceLogFile(context, prefs, new File(dir, CLEANUP_LOG), "cleanup");
        } catch (RuntimeException e) {
            ApplicationErrorLog.add(context, "DNS service log bridge failed: " + e.getMessage());
        }
    }

    private static void syncServiceLogFile(Context context, SharedPreferences prefs, File file,
                                           String label) {
        if (context == null || prefs == null || file == null || !file.exists()) {
            return;
        }
        String key = serviceLogOffsetKey(label);
        if (!file.canRead()) {
            recordUnreadableServiceLog(context, prefs, label);
            return;
        }
        long length = file.length();
        long offset = prefs.getLong(key, -1L);
        if (length <= 0L) {
            prefs.edit()
                    .putLong(key, 0L)
                    .putBoolean(UNREADABLE_SERVICE_LOG_PREFIX + label, false)
                    .apply();
            return;
        }
        if (offset < 0L) {
            offset = Math.max(0L, length - MAX_SERVICE_LOG_READ);
        } else if (offset > length) {
            offset = 0L;
        }
        if (length <= offset) {
            return;
        }
        long readStart = offset;
        if (length - readStart > MAX_SERVICE_LOG_READ) {
            readStart = length - MAX_SERVICE_LOG_READ;
            ApplicationErrorLog.add(context, "DNS service " + label
                    + " log advanced while app was closed; older service events were skipped");
        }
        String chunk = readFileRange(file, readStart, length - readStart);
        if (chunk != null) {
            bridgeServiceLogLines(context, label, chunk);
            prefs.edit()
                    .putLong(key, length)
                    .putBoolean(UNREADABLE_SERVICE_LOG_PREFIX + label, false)
                    .apply();
            return;
        }
        recordUnreadableServiceLog(context, prefs, label);
    }

    private static void recordUnreadableServiceLog(Context context, SharedPreferences prefs,
                                                   String label) {
        if (!prefs.getBoolean(UNREADABLE_SERVICE_LOG_PREFIX + label, false)) {
            ApplicationErrorLog.add(context, "DNS service " + label
                    + " log could not be read; root log file permissions may need repair");
            Log.w(TAG, "DNS service " + label + " log could not be read by the app");
        }
        prefs.edit().putBoolean(UNREADABLE_SERVICE_LOG_PREFIX + label, true).apply();
    }

    private static void bridgeServiceLogLines(Context context, String label, String chunk) {
        String[] lines = chunk.split("\\r?\\n");
        List<String> cleaned = new ArrayList<>();
        for (String line : lines) {
            String clean = sanitizeServiceLogLine(line);
            if (!clean.isEmpty()) {
                cleaned.add(clean);
            }
        }
        int start = Math.max(0, cleaned.size() - MAX_SERVICE_LOG_LINES);
        for (int i = start; i < cleaned.size(); i++) {
            String bridgedLine = "DNS service " + label + ": " + cleaned.get(i);
            Log.i(TAG, bridgedLine);
            ApplicationErrorLog.add(context, bridgedLine);
        }
    }

    private static String sanitizeServiceLogLine(String line) {
        String clean = line == null ? "" : line.trim().replace('\r', ' ').replace('\n', ' ');
        clean = clean.replaceAll("\\s+", " ");
        clean = formatServiceEventTimestamp(clean);
        if (clean.length() > MAX_SERVICE_LOG_LINE_CHARS) {
            clean = clean.substring(0, MAX_SERVICE_LOG_LINE_CHARS);
        }
        return clean;
    }

    private static String formatServiceEventTimestamp(String clean) {
        if (clean == null || clean.isEmpty()) {
            return "";
        }
        int separator = clean.indexOf(' ');
        if (separator <= 0 || separator >= clean.length() - 1) {
            return clean;
        }
        String firstToken = clean.substring(0, separator);
        for (int i = 0; i < firstToken.length(); i++) {
            if (!Character.isDigit(firstToken.charAt(i))) {
                return clean;
            }
        }
        try {
            long epochSeconds = Long.parseLong(firstToken);
            String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
                    .format(new Date(epochSeconds * 1000L));
            return timestamp + " " + clean.substring(separator + 1);
        } catch (NumberFormatException e) {
            return clean;
        }
    }

    private static void appendServiceLogBridgeStatus(Context context, StringBuilder out,
                                                     String label, File file) {
        SharedPreferences prefs = context.getApplicationContext()
                .getSharedPreferences(SERVICE_LOG_PREFS, Context.MODE_PRIVATE);
        long offset = prefs.getLong(serviceLogOffsetKey(label), -1L);
        out.append(label)
                .append("_log_exists=").append(file != null && file.exists())
                .append(" readable=").append(file != null && file.canRead())
                .append(" size=").append(file == null || !file.exists() ? 0L : file.length())
                .append(" bridged_offset=").append(offset)
                .append('\n');
    }

    private static String serviceLogOffsetKey(String label) {
        return "offset_" + label;
    }

    private static void appendTailFileValue(StringBuilder out, String label, File file, int maxBytes) {
        out.append(label).append("=\n");
        if (file == null || !file.exists()) {
            out.append("missing\n");
            return;
        }
        long length = file.length();
        if (length <= 0L) {
            out.append("empty\n");
            return;
        }
        long readStart = Math.max(0L, length - Math.max(1, maxBytes));
        String value = readFileRange(file, readStart, length - readStart);
        if (value == null || value.trim().isEmpty()) {
            out.append("unreadable or empty\n");
            return;
        }
        out.append(value.trim()).append('\n');
    }

    private static void appendRecentServiceEvents(StringBuilder out, String label, File file) {
        if (out == null || label == null || file == null || !file.exists() || file.length() <= 0L) {
            return;
        }
        long length = file.length();
        long readStart = Math.max(0L, length - MAX_DIAGNOSTIC_LOG_TAIL);
        String value = readFileRange(file, readStart, length - readStart);
        if (value == null || value.trim().isEmpty()) {
            return;
        }
        String[] lines = value.split("\\r?\\n");
        List<String> cleaned = new ArrayList<>();
        for (String line : lines) {
            String clean = sanitizeServiceLogLine(line);
            if (!clean.isEmpty()) {
                cleaned.add(clean);
            }
        }
        int start = Math.max(0, cleaned.size() - MAX_SERVICE_LOG_LINES);
        for (int i = start; i < cleaned.size(); i++) {
            if (out.length() > 0) {
                out.append('\n');
            }
            out.append(label).append(": ").append(cleaned.get(i));
        }
    }

    private static String readFileRange(File file, long offset, long bytes) {
        if (file == null || bytes <= 0L) {
            return "";
        }
        int length = (int) Math.min(bytes, Integer.MAX_VALUE);
        byte[] buffer = new byte[length];
        try (RandomAccessFile randomAccessFile = new RandomAccessFile(file, "r")) {
            randomAccessFile.seek(Math.max(0L, offset));
            int read = randomAccessFile.read(buffer);
            if (read <= 0) {
                return "";
            }
            return new String(buffer, 0, read, StandardCharsets.UTF_8);
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    private static String privateDnsDashboardLine(Context context) {
        String warning = androidPrivateDnsWarning(context);
        if (warning != null) {
            return "\nAndroid Private DNS warning: " + warning;
        }
        return "\nAndroid Private DNS: " + readAndroidPrivateDnsMode(context);
    }

    private static void appendAndroidDnsCompatibility(Context context, StringBuilder out) {
        boolean uidScopedCapture = !parseUidList(G.dnsHijackCaptureUids()).isEmpty();
        out.append("capture_scope=").append(uidScopedCapture
                ? "udp_tcp_port_53_output_uid_scoped_except_daemon_mark"
                : "udp_tcp_port_53_output_and_prerouting_except_daemon_mark").append('\n');
        out.append("uid_scoped_prerouting_capture=").append(uidScopedCapture
                ? "disabled_forwarded_packets_do_not_expose_app_uid"
                : "enabled").append('\n');
        out.append("uid_scoped_android_resolver_warning=").append(uidScopedCapture
                ? "system_resolver_packets_may_use_system_uid_use_empty_uid_scope_for_full_capture"
                : "none").append('\n');
        out.append("encrypted_dns_note=Private DNS/DoT on 853 and in-app DoH are not port-53 DNS and can bypass NAT capture\n");
        out.append("daemon_control_auth=token_required\n");
        out.append("daemon_control_socket_uid=").append(context.getApplicationInfo().uid).append('\n');
        out.append("daemon_socket_mark=").append(DAEMON_SOCKET_MARK).append('\n');
        out.append("daemon_mark_output_bypass=enabled_to_prevent_daemon_upstream_recursion\n");
        out.append("daemon_mark_filter_bypass=enabled_for_daemon_upstream_packets\n");
        out.append("root_uid_output_bypass=fallback_only_when_mark_match_is_unavailable\n");
        out.append("root_uid_filter_bypass=fallback_only_when_daemon_socket_mark_is_unavailable\n");
        out.append("root_uid_capture_warning=").append(rootUidBypassWarning()).append('\n');
        out.append("private_dns_mode=").append(readAndroidPrivateDnsMode(context)).append('\n');
        String specifier = readAndroidPrivateDnsSpecifier(context);
        out.append("private_dns_specifier=")
                .append(specifier.isEmpty() ? "none" : specifier).append('\n');
        String warning = androidPrivateDnsWarning(context);
        out.append("private_dns_capture_warning=")
                .append(warning == null ? "none" : warning).append('\n');
        out.append("android_app_battery_optimized=").append(androidAppBatteryOptimized(context)).append('\n');
        out.append("root_daemon_storage=").append(workDirStorageLabel(context)).append('\n');
        out.append("root_daemon_power_scope=outside_android_app_process\n");
        out.append("root_watchdog_scope=supervisor_script_restarts_daemon_when_heartbeat_stales\n");
        out.append("root_watchdog_fail_open=removes_dns_redirects_until_daemon_is_ready\n");
    }

    private static String androidAppBatteryOptimized(Context context) {
        if (context == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return "unsupported";
        }
        try {
            return String.valueOf(Api.batteryOptimized(context));
        } catch (RuntimeException e) {
            return "unknown";
        }
    }

    private static String androidPowerDashboardLine(Context context) {
        String optimized = androidAppBatteryOptimized(context);
        if ("true".equals(optimized)) {
            return "Power: root daemon watchdog runs outside app power limits and fails open while restarting; scheduled app updates may be delayed";
        }
        if ("false".equals(optimized)) {
            return "Power: root daemon watchdog runs outside app power limits and fails open while restarting; app updates are not battery-optimized";
        }
        return "Power: root daemon watchdog runs outside app power limits and fails open while restarting; app update power state " + optimized;
    }

    private static String rootUidBypassWarning() {
        return "UID 0 OUTPUT DNS is only used as a compatibility fallback if mark matching is unavailable; "
                + "that fallback can let root-owned system DNS bypass capture";
    }

    private static String daemonMarkSupportLabel(long supported) {
        if (supported == 1L) {
            return "supported";
        }
        if (supported == 0L) {
            return "unavailable";
        }
        return "unknown";
    }

    private static String yesNoUnknown(long value) {
        if (value == 1L) {
            return "ready";
        }
        if (value == 0L) {
            return "missing";
        }
        return "unknown";
    }

    private static String readAndroidPrivateDnsMode(Context context) {
        if (context == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return "unsupported";
        }
        try {
            String value = Settings.Global.getString(context.getContentResolver(), PRIVATE_DNS_MODE);
            return value == null || value.trim().isEmpty()
                    ? "unknown"
                    : value.trim().toLowerCase(Locale.US);
        } catch (RuntimeException e) {
            return "unknown";
        }
    }

    private static String readAndroidPrivateDnsSpecifier(Context context) {
        if (context == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return "";
        }
        try {
            String value = Settings.Global.getString(context.getContentResolver(), PRIVATE_DNS_SPECIFIER);
            return value == null ? "" : value.trim();
        } catch (RuntimeException e) {
            return "";
        }
    }

    private static boolean privateDnsModeCanBypass(String mode) {
        if (mode == null) {
            return false;
        }
        String normalized = mode.trim().toLowerCase(Locale.US);
        return "opportunistic".equals(normalized) || "hostname".equals(normalized);
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

    public static String runCaptureProbe(Context context) {
        if (context == null) {
            return "capture_probe=unavailable\nreason=missing_context\n";
        }
        if (!G.enableDnsHijack()) {
            return logCaptureProbeResult(context,
                    "capture_probe=disabled\nreason=dns_protection_disabled\n");
        }

        int appUid = android.os.Process.myUid();
        List<Integer> captureUids = parseUidList(G.dnsHijackCaptureUids());
        List<Integer> bypassUids = parseUidList(G.dnsHijackBypassUids());
        if (bypassUids.contains(appUid)) {
            return logCaptureProbeResult(context,
                    "capture_probe=skipped\nreason=app_uid_bypassed\napp_uid=" + appUid + "\n");
        }
        if (!captureUids.isEmpty() && !captureUids.contains(appUid)) {
            return logCaptureProbeResult(context,
                    "capture_probe=skipped\nreason=app_uid_not_in_capture_scope\napp_uid="
                            + appUid + "\n");
        }

        String beforeRaw = queryControl(context, "status");
        Map<String, String> beforeValues = parseKeyValueLines(beforeRaw);
        if (!"1".equals(beforeValues.get("running"))) {
            return logCaptureProbeResult(context,
                    "capture_probe=unavailable\nreason=daemon_not_running\ncontrol_status="
                            + safeLogValue(compactControlResponse(beforeRaw)) + "\n");
        }

        long beforeQueries = parseLong(beforeValues.get("queries"), -1L);
        String domain = "afwall-capture-" + Long.toHexString(System.currentTimeMillis())
                + ".example.com";
        byte[] query = buildDnsLookupQuery(domain, DNS_QTYPE_A);
        int timeoutMs = Math.min(Math.max(G.dnsHijackTimeoutMs(), 500), 2000);
        ProbeResult udpResult = query == null
                ? new ProbeResult("build_error", -1, -1)
                : probeUdpUpstreamDirect(new UpstreamTarget("1.1.1.1", 53, "udp"),
                        timeoutMs, query);
        sleepQuietly(250L);

        String afterRaw = queryControl(context, "status");
        Map<String, String> afterValues = parseKeyValueLines(afterRaw);
        long afterQueries = parseLong(afterValues.get("queries"), -1L);
        boolean observedByCounter = beforeQueries >= 0L && afterQueries > beforeQueries;
        String afterLogsRaw = queryControl(context, "logs");
        boolean observedDomain = queryLogsContainDomain(afterLogsRaw, domain);
        boolean observedByDaemon = observedDomain || observedByCounter;
        boolean dnsResponseReceived = udpResult.bytes > 0;
        String probeStatus = observedDomain
                ? (dnsResponseReceived ? "captured" : "captured_no_response")
                : observedByCounter
                ? (dnsResponseReceived ? "captured_counter_only" : "captured_counter_only_no_response")
                : dnsResponseReceived ? "bypassed_or_not_counted" : "not_observed";

        StringBuilder out = new StringBuilder();
        out.append("capture_probe=").append(probeStatus).append('\n');
        out.append("probe_scope=app_process_udp_output_port_53\n");
        out.append("android_system_resolver_probe=not_tested_may_use_system_uid\n");
        out.append("forwarded_prerouting_probe=not_tested_requires_external_or_tethered_client\n");
        out.append("encrypted_dns_probe=not_tested_private_dns_dot_doh_can_bypass_port_53\n");
        out.append("app_uid=").append(appUid).append('\n');
        out.append("probe_target=udp://1.1.1.1:53\n");
        out.append("test_domain=").append(domain).append('\n');
        out.append("daemon_observed_domain=").append(observedDomain).append('\n');
        out.append("dns_response_received=").append(dnsResponseReceived).append('\n');
        out.append("daemon_queries_before=").append(beforeQueries).append('\n');
        out.append("daemon_queries_after=").append(afterQueries).append('\n');
        out.append("daemon_query_logging=")
                .append(emptyFallback(afterValues.get("query_logging"), "unknown")).append('\n');
        out.append("udp_probe_status=").append(udpResult.status).append('\n');
        out.append("udp_probe_bytes=").append(udpResult.bytes).append('\n');
        out.append("udp_probe_rcode=").append(udpResult.rcode).append('\n');
        out.append("timeout_ms=").append(timeoutMs).append('\n');
        if (observedByCounter && !observedDomain) {
            out.append("proof_note=daemon query counter increased, but recent logs did not include the test domain\n");
        }
        if (!observedDomain && "0".equals(afterValues.get("query_logging"))) {
            out.append("proof_note=query logging is disabled, so exact-domain capture proof is unavailable\n");
        }
        if (!captureUids.isEmpty()) {
            out.append("uid_scope_note=this probe uses an app-owned UDP socket; ")
                    .append("Android system resolver traffic may use a system UID\n");
        }
        if (!parseInterfaceList(G.dnsHijackCaptureInterfaces()).isEmpty()
                || !parseInterfaceList(G.dnsHijackBypassInterfaces()).isEmpty()) {
            out.append("scope_note=interface capture or bypass rules are configured; ")
                    .append("this probe validates the app process route only\n");
        }
        if (!observedByDaemon) {
            out.append("action_hint=repair DNS protection, then retry; if scoped capture is enabled, ")
                    .append("test with an app in the captured scope\n");
        } else if (!dnsResponseReceived) {
            out.append("action_hint=capture was observed, but no DNS response returned; ")
                    .append("check upstream DNS, fail-open/strict settings, and service events\n");
        }
        return logCaptureProbeResult(context, out.toString());
    }

    private static boolean queryLogsContainDomain(String raw, String domain) {
        if (domain == null || domain.trim().isEmpty()) {
            return false;
        }
        String normalized = normalizeDomain(domain);
        if (normalized.isEmpty()) {
            return false;
        }
        List<QueryEntry> entries = parseQueryEntries(raw);
        for (QueryEntry entry : entries) {
            if (entry != null && normalized.equals(entry.domain)) {
                return true;
            }
        }
        return false;
    }

    private static String logCaptureProbeResult(Context context, String result) {
        ApplicationErrorLog.add(context, "DNS capture probe result: "
                + compactControlResponse(result));
        return result;
    }

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
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
            case RULE_APP_ALLOW_EXACT:
                added = G.appendDnsHijackAppAllowExact(parseQueryUid(entry), domain);
                break;
            case RULE_APP_BLOCK_EXACT:
                added = G.appendDnsHijackAppBlockExact(parseQueryUid(entry), domain);
                break;
            case RULE_APP_ALLOW_SUFFIX:
                added = G.appendDnsHijackAppAllowSuffix(parseQueryUid(entry), domain);
                break;
            case RULE_APP_BLOCK_SUFFIX:
                added = G.appendDnsHijackAppBlockSuffix(parseQueryUid(entry), domain);
                break;
            default:
                return false;
        }
        if (added) {
            ApplicationErrorLog.add(context, "DNS query action added rule for " + domain
                    + " uid=" + parseQueryUid(entry) + " action=" + action);
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
        commands.add("if [ -x " + supervisor + " ]; then " + supervisor
                + " status 2>&1 || true; else echo 'supervisor missing'; fi");
        commands.add("echo '[DNS redirect status]'");
        commands.addAll(buildRootRedirectStatusCommands(context));
        commands.add("echo '[pid]'");
        commands.add("cat " + shellQuote(new File(workDir(context), PID).getAbsolutePath()) + " 2>&1 || true");
        commands.add("echo '[IPv4 DNS NAT OUTPUT]'");
        commands.add(iptables + " -t nat -S OUTPUT 2>&1 | grep 'afwall-dns' || true");
        commands.add("echo '[IPv4 DNS filter daemon bypass]'");
        commands.add(iptables + " -S OUTPUT 2>&1 | grep " + shellQuote(DAEMON_SOCKET_MARK)
                + " || true");
        commands.add("echo '[IPv4 DNS NAT chains]'");
        commands.add(iptables + " -t nat -S " + CHAIN_V4 + " 2>&1 || true");
        commands.add(iptables + " -t nat -S " + CHAIN_V4_PRE + " 2>&1 || true");
        commands.add("echo '[IPv6 DNS NAT OUTPUT]'");
        commands.add(ip6tables + " -t nat -S OUTPUT 2>&1 | grep 'afwall-dns6' || true");
        commands.add("echo '[IPv6 DNS filter daemon bypass]'");
        commands.add(ip6tables + " -S OUTPUT 2>&1 | grep " + shellQuote(DAEMON_SOCKET_MARK)
                + " || true");
        commands.add("echo '[IPv6 DNS NAT chains]'");
        commands.add(ip6tables + " -t nat -S " + CHAIN_V6 + " 2>&1 || true");
        commands.add(ip6tables + " -t nat -S " + CHAIN_V6_PRE + " 2>&1 || true");
        commands.add("echo '[nft DNS redirect tables]'");
        commands.add("if command -v nft >/dev/null 2>&1; then "
                + "nft list table ip " + NFT_TABLE_V4 + " 2>&1 || true; "
                + "nft list table ip6 " + NFT_TABLE_V6 + " 2>&1 || true; "
                + "else echo 'nft missing'; fi");
        commands.addAll(buildMagiskModuleStatusCommands(context));
        commands.add("echo '[DNS fallback stale cleanup logs]'");
        commands.add(buildFallbackRootLogTailCommand(BOOT_LOG));
        commands.add(buildFallbackRootLogTailCommand(CLEANUP_LOG));
        return commands;
    }

    public static List<String> buildMagiskModuleStatusCommands(Context context) {
        List<String> commands = new ArrayList<>();
        File dir = workDir(context);
        commands.add("echo '[DNS Magisk module]'");
        commands.add("echo 'expected_script_version=" + MAGISK_SCRIPT_VERSION + "'");
        commands.add("PKG=" + shellQuote(context.getPackageName()) + "; "
                + "if pm path \"$PKG\" >/dev/null 2>&1; then "
                + "echo 'app_package=installed'; "
                + "else echo 'app_package=missing'; fi");
        commands.add("MOD=" + shellQuote(MAGISK_MODULE_DIR) + "; "
                + "if [ -d \"$MOD\" ]; then "
                + "echo 'magisk_module=installed'; "
                + "[ -f \"$MOD/disable\" ] && echo 'magisk_module_disabled=1' || echo 'magisk_module_disabled=0'; "
                + "[ -f \"$MOD/remove\" ] && echo 'magisk_module_remove_pending=1' || echo 'magisk_module_remove_pending=0'; "
                + "if [ -f \"$MOD/" + MAGISK_SERVICE_SCRIPT + "\" ]; then "
                + "grep '^AFWALL_DNS_MODULE_SCRIPT_VERSION=' \"$MOD/" + MAGISK_SERVICE_SCRIPT + "\" 2>/dev/null "
                + "| sed 's/^AFWALL_DNS_MODULE_SCRIPT_VERSION=/installed_service_script_version=/' || true; "
                + "else echo 'installed_service_script_missing=1'; fi; "
                + "if [ -f \"$MOD/" + MAGISK_UNINSTALL_SCRIPT + "\" ]; then "
                + "grep '^AFWALL_DNS_MODULE_SCRIPT_VERSION=' \"$MOD/" + MAGISK_UNINSTALL_SCRIPT + "\" 2>/dev/null "
                + "| sed 's/^AFWALL_DNS_MODULE_SCRIPT_VERSION=/installed_uninstall_script_version=/' || true; "
                + "else echo 'installed_uninstall_script_missing=1'; fi; "
                + "ls -la \"$MOD\" 2>&1; "
                + "else echo 'magisk_module=missing'; fi");
        commands.add("echo '[AFWall prepared module files]'");
        commands.add("SERVICE=" + shellQuote(new File(dir, MAGISK_SERVICE_SCRIPT).getAbsolutePath()) + "; "
                + "UNINSTALL=" + shellQuote(new File(dir, MAGISK_UNINSTALL_SCRIPT).getAbsolutePath()) + "; "
                + "PROP=" + shellQuote(new File(dir, MAGISK_MODULE_PROP).getAbsolutePath()) + "; "
                + "for f in \"$PROP\" \"$SERVICE\" \"$UNINSTALL\"; do "
                + "if [ -e \"$f\" ]; then ls -l \"$f\"; else echo \"$f missing\"; fi; done; "
                + "if [ -f \"$SERVICE\" ]; then "
                + "grep '^AFWALL_DNS_MODULE_SCRIPT_VERSION=' \"$SERVICE\" 2>/dev/null "
                + "| sed 's/^AFWALL_DNS_MODULE_SCRIPT_VERSION=/prepared_service_script_version=/' || true; "
                + "else echo 'prepared_service_script_missing=1'; fi; "
                + "if [ -f \"$UNINSTALL\" ]; then "
                + "grep '^AFWALL_DNS_MODULE_SCRIPT_VERSION=' \"$UNINSTALL\" 2>/dev/null "
                + "| sed 's/^AFWALL_DNS_MODULE_SCRIPT_VERSION=/prepared_uninstall_script_version=/' || true; "
                + "else echo 'prepared_uninstall_script_missing=1'; fi");
        commands.add("echo '[DNS control socket permissions]'");
        commands.add("SOCK=" + shellQuote(new File(dir, SOCKET).getAbsolutePath()) + "; "
                + "if [ -S \"$SOCK\" ]; then ls -l \"$SOCK\" 2>&1; "
                + "else echo 'control_socket=missing'; fi");
        commands.add("echo '[DNS module log]'");
        commands.add(buildFallbackRootLogTailCommand(MAGISK_MODULE_LOG));
        commands.add("echo '[legacy DNS root startup hooks]'");
        commands.add("found=0; for f in /data/adb/service.d/" + BOOT_SCRIPT
                + " /su/su.d/" + BOOT_SCRIPT
                + " /system/su.d/" + BOOT_SCRIPT
                + " /system/etc/init.d/" + BOOT_SCRIPT
                + " /data/adb/service.d/" + CLEANUP_SCRIPT
                + " /su/su.d/" + CLEANUP_SCRIPT
                + " /system/su.d/" + CLEANUP_SCRIPT
                + " /system/etc/init.d/" + CLEANUP_SCRIPT
                + "; do if [ -f \"$f\" ]; then ls -l \"$f\"; found=1; fi; done; "
                + "[ \"$found\" = 1 ] || echo 'no legacy root startup hooks installed'");
        return commands;
    }

    private static String buildFallbackRootLogTailCommand(String logName) {
        String path = "/data/local/tmp/" + logName;
        return "if [ -f " + shellQuote(path) + " ]; then echo " + shellQuote(path)
                + "; tail -n 30 " + shellQuote(path) + " 2>/dev/null || cat "
                + shellQuote(path) + " 2>/dev/null; else echo " + shellQuote(path)
                + " missing; fi";
    }

    public static List<String> buildRootRedirectStatusCommands(Context context) {
        List<String> commands = new ArrayList<>();
        String iptables = shellQuote(Api.getBinaryPath(context, false));
        String ip6tables = shellQuote(Api.getBinaryPath(context, true));
        appendRedirectStatusCommands(commands, "dns_redirect_ipv4", iptables,
                CHAIN_V4, CHAIN_V4_PRE, "ip", NFT_TABLE_V4);
        appendRedirectStatusCommands(commands, "dns_redirect_ipv6", ip6tables,
                CHAIN_V6, CHAIN_V6_PRE, "ip6", NFT_TABLE_V6);
        return commands;
    }

    public static String formatRootRedirectStatus(String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            return "Redirect rules: root check failed";
        }
        Map<String, String> values = parseKeyValueLines(raw);
        if (values.isEmpty()) {
            return "Redirect rules: root check failed";
        }
        String ipv4 = redirectFamilyStatus(values, "dns_redirect_ipv4");
        String ipv6 = G.enableIPv6()
                ? redirectFamilyStatus(values, "dns_redirect_ipv6")
                : "disabled";
        return "Redirect rules: IPv4 " + ipv4 + " | IPv6 " + ipv6;
    }

    public static String formatDashboardReadiness(DnsDashboardSnapshot snapshot, String rootStatusRaw) {
        if (snapshot == null || !snapshot.enabled) {
            return "Readiness: disabled";
        }
        List<String> blockers = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        if (!snapshot.daemonRunning) {
            blockers.add("daemon unavailable");
        }
        if (!snapshot.listenersReady) {
            blockers.add("listener missing");
        }
        if (redirectStatusMissingDaemonFilterBypass(rootStatusRaw)) {
            blockers.add("daemon upstream filter bypass missing");
        } else if (!isRootRedirectStatusHealthy(rootStatusRaw)) {
            blockers.add("redirect rules missing");
        }
        if (!snapshot.upstreamProbeHealthy) {
            warnings.add("upstream probe failed");
        }
        if (snapshot.privateDnsMayBypass) {
            warnings.add("Android Private DNS may bypass capture");
        }
        if (redirectStatusUsesUidFallback(rootStatusRaw)) {
            warnings.add("daemon mark unavailable; UID 0 DNS may bypass capture");
        } else if (snapshot.rootUidMayBypass) {
            warnings.add("root/system DNS may bypass capture");
        }
        if (!blockers.isEmpty()) {
            return "Readiness: repair needed (" + joinLabels(blockers) + ")";
        }
        if (!warnings.isEmpty()) {
            return "Readiness: usable with warning (" + joinLabels(warnings) + ")";
        }
        return preroutingRedirectExpected()
                ? "Readiness: ready for local and forwarded UDP/TCP port-53 capture"
                : "Readiness: ready for UID-scoped app-owned UDP/TCP port-53 capture";
    }

    private static boolean redirectStatusUsesUidFallback(String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            return false;
        }
        Map<String, String> values = parseKeyValueLines(raw);
        if (values.isEmpty()) {
            return false;
        }
        if (redirectFamilyUsesUidFallback(values, "dns_redirect_ipv4")) {
            return true;
        }
        return G.enableIPv6() && redirectFamilyUsesUidFallback(values, "dns_redirect_ipv6");
    }

    private static boolean redirectStatusMissingDaemonFilterBypass(String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            return false;
        }
        Map<String, String> values = parseKeyValueLines(raw);
        if (values.isEmpty()) {
            return false;
        }
        if (redirectFamilyMissingDaemonFilterBypass(values, "dns_redirect_ipv4")) {
            return true;
        }
        return G.enableIPv6()
                && redirectFamilyMissingDaemonFilterBypass(values, "dns_redirect_ipv6");
    }

    public static boolean isRootRedirectStatusHealthy(String raw) {
        if (!G.enableDnsHijack()) {
            return true;
        }
        if (raw == null || raw.trim().isEmpty()) {
            return false;
        }
        Map<String, String> values = parseKeyValueLines(raw);
        if (values.isEmpty()) {
            return false;
        }
        if (!redirectFamilyHealthy(values, "dns_redirect_ipv4")) {
            return false;
        }
        return !G.enableIPv6() || redirectFamilyHealthy(values, "dns_redirect_ipv6");
    }

    private static void appendRedirectStatusCommands(List<String> commands, String prefix,
                                                     String iptables, String chain,
                                                     String preChain, String nftFamily,
                                                     String nftTable) {
        int port = G.dnsHijackPort(DEFAULT_PORT);
        commands.add(buildChainStatusCommand(prefix + "_chain", iptables, chain));
        commands.add(buildChainStatusCommand(prefix + "_pre_chain", iptables, preChain));
        commands.add(buildRuleStatusCommand(prefix + "_output_udp", iptables,
                "OUTPUT", "udp", chain));
        commands.add(buildRuleStatusCommand(prefix + "_output_tcp", iptables,
                "OUTPUT", "tcp", chain));
        commands.add(buildRuleStatusCommand(prefix + "_prerouting_udp", iptables,
                "PREROUTING", "udp", preChain));
        commands.add(buildRuleStatusCommand(prefix + "_prerouting_tcp", iptables,
                "PREROUTING", "tcp", preChain));
        commands.add(buildDaemonMarkReturnStatusCommand(prefix + "_output_daemon_mark_return",
                iptables, chain));
        commands.add(buildUid0ReturnStatusCommand(prefix + "_output_uid0_return",
                iptables, chain));
        commands.add(buildDaemonMarkFilterAcceptStatusCommand(
                prefix + "_filter_daemon_mark_accept", iptables));
        commands.add(buildUid0FilterAcceptStatusCommand(
                prefix + "_filter_uid0_dns_accept", iptables));
        commands.add(buildRedirectTargetStatusCommand(prefix + "_chain_udp_redirect",
                iptables, chain, "udp", port));
        commands.add(buildRedirectTargetStatusCommand(prefix + "_chain_tcp_redirect",
                iptables, chain, "tcp", port));
        commands.add(buildRedirectTargetStatusCommand(prefix + "_pre_chain_udp_redirect",
                iptables, preChain, "udp", port));
        commands.add(buildRedirectTargetStatusCommand(prefix + "_pre_chain_tcp_redirect",
                iptables, preChain, "tcp", port));
        commands.add(buildNftTableStatusCommand(prefix + "_nft_table", nftFamily, nftTable));
        commands.add(buildNftDaemonMarkReturnStatusCommand(
                prefix + "_nft_output_daemon_mark_return", nftFamily, nftTable));
        commands.add(buildNftUid0ReturnStatusCommand(prefix + "_nft_output_uid0_return",
                nftFamily, nftTable));
        commands.add(buildNftRedirectStatusCommand(prefix + "_nft_output_udp",
                nftFamily, nftTable, NFT_OUTPUT, "udp", port));
        commands.add(buildNftRedirectStatusCommand(prefix + "_nft_output_tcp",
                nftFamily, nftTable, NFT_OUTPUT, "tcp", port));
        commands.add(buildNftRedirectStatusCommand(prefix + "_nft_prerouting_udp",
                nftFamily, nftTable, NFT_PREROUTING, "udp", port));
        commands.add(buildNftRedirectStatusCommand(prefix + "_nft_prerouting_tcp",
                nftFamily, nftTable, NFT_PREROUTING, "tcp", port));
    }

    private static String buildChainStatusCommand(String key, String iptables, String chain) {
        return "if " + iptables + " -t nat -S " + shellQuote(chain)
                + " >/dev/null 2>&1; then echo " + key + "=1; else echo "
                + key + "=0; fi";
    }

    private static String buildRuleStatusCommand(String key, String iptables, String parentChain,
                                                 String protocol, String targetChain) {
        String pattern = "-p " + protocol + " .*--dport 53.*-j " + targetChain;
        return "if " + iptables + " -t nat -S " + shellQuote(parentChain)
                + " 2>/dev/null | grep -q -- " + shellQuote(pattern)
                + "; then echo " + key + "=1; else echo " + key + "=0; fi";
    }

    private static String buildDaemonMarkReturnStatusCommand(String key, String iptables,
                                                             String chain) {
        return "if " + buildIptablesDaemonMarkReturnCheck(iptables, chain)
                + "; then echo " + key + "=1; else echo " + key + "=0; fi";
    }

    private static String buildUid0ReturnStatusCommand(String key, String iptables,
                                                       String chain) {
        return "if " + buildIptablesUid0ReturnCheck(iptables, chain)
                + "; then echo " + key + "=1; else echo " + key + "=0; fi";
    }

    private static String buildDaemonMarkFilterAcceptStatusCommand(String key, String iptables) {
        return "if " + buildIptablesDaemonMarkFilterAcceptCheck(iptables)
                + "; then echo " + key + "=1; else echo " + key + "=0; fi";
    }

    private static String buildUid0FilterAcceptStatusCommand(String key, String iptables) {
        return "if " + buildIptablesUid0FilterAcceptCheck(iptables)
                + "; then echo " + key + "=1; else echo " + key + "=0; fi";
    }

    private static String buildRedirectTargetStatusCommand(String key, String iptables, String chain,
                                                           String protocol, int port) {
        String pattern = "-p " + protocol + " .*--dport 53.*-j REDIRECT.*--to-ports " + port;
        return "if " + iptables + " -t nat -S " + shellQuote(chain)
                + " 2>/dev/null | grep -q -- " + shellQuote(pattern)
                + "; then echo " + key + "=1; else echo " + key + "=0; fi";
    }

    private static String buildIptablesRedirectHealthyCondition(String iptables, String chain,
                                                                String preChain, int port) {
        List<String> checks = new ArrayList<>();
        checks.add(buildIptablesRuleCheck(iptables, "OUTPUT", "udp", chain));
        checks.add(buildIptablesRuleCheck(iptables, "OUTPUT", "tcp", chain));
        if (preroutingRedirectExpected()) {
            checks.add(buildIptablesRuleCheck(iptables, "PREROUTING", "udp", preChain));
            checks.add(buildIptablesRuleCheck(iptables, "PREROUTING", "tcp", preChain));
        }
        checks.add(buildIptablesRecursionGuardCheck(iptables, chain));
        checks.add(buildIptablesDaemonPathFilterCheck(iptables, chain));
        checks.add(buildIptablesRedirectTargetCheck(iptables, chain, "udp", port));
        checks.add(buildIptablesRedirectTargetCheck(iptables, chain, "tcp", port));
        if (preroutingRedirectExpected()) {
            checks.add(buildIptablesRedirectTargetCheck(iptables, preChain, "udp", port));
            checks.add(buildIptablesRedirectTargetCheck(iptables, preChain, "tcp", port));
        }
        return joinShellChecks(checks);
    }

    private static String buildRedirectInstallVerificationCommand(Context context, boolean ipv6) {
        String iptables = shellQuote(Api.getBinaryPath(context, ipv6));
        String chain = ipv6 ? CHAIN_V6 : CHAIN_V4;
        String preChain = ipv6 ? CHAIN_V6_PRE : CHAIN_V4_PRE;
        String family = ipv6 ? "ip6" : "ip";
        String table = ipv6 ? NFT_TABLE_V6 : NFT_TABLE_V4;
        int port = G.dnsHijackPort(DEFAULT_PORT);
        String iptablesReady = buildIptablesRedirectHealthyCondition(iptables, chain, preChain, port);
        String nftReady = buildNftRedirectHealthyCondition(family, table, port, iptables);
        String label = ipv6 ? "IPv6" : "IPv4";
        return "if ( " + iptablesReady + " ) || ( " + nftReady + " ); then true; else "
                + "echo 'DNS redirect install verification failed for " + label + "'; false; fi; #";
    }

    private static String buildIptablesRuleCheck(String iptables, String parentChain,
                                                 String protocol, String targetChain) {
        String pattern = "-p " + protocol + " .*--dport 53.*-j " + targetChain;
        return iptables + " -t nat -S " + shellQuote(parentChain)
                + " 2>/dev/null | grep -q -- " + shellQuote(pattern);
    }

    private static String buildIptablesRecursionGuardCheck(String iptables, String chain) {
        return "( " + buildIptablesDaemonMarkReturnCheck(iptables, chain)
                + " || " + buildIptablesUid0ReturnCheck(iptables, chain) + " )";
    }

    private static String buildIptablesDaemonPathFilterCheck(String iptables, String chain) {
        return "( ( " + buildIptablesDaemonMarkReturnCheck(iptables, chain)
                + " && " + buildIptablesDaemonMarkFilterAcceptCheck(iptables)
                + " ) || ( " + buildIptablesUid0ReturnCheck(iptables, chain)
                + " && " + buildIptablesUid0FilterAcceptCheck(iptables) + " ) )";
    }

    private static String buildIptablesDaemonMarkReturnCheck(String iptables, String chain) {
        String pattern = "-m mark .*--mark " + DAEMON_SOCKET_MARK + ".*-j RETURN";
        return iptables + " -t nat -S " + shellQuote(chain)
                + " 2>/dev/null | grep -q -- " + shellQuote(pattern);
    }

    private static String buildIptablesDaemonMarkFilterAcceptCheck(String iptables) {
        String pattern = "-m mark .*--mark " + DAEMON_SOCKET_MARK + ".*-j ACCEPT";
        return "( " + iptables + " -S OUTPUT 2>/dev/null | grep -q -- "
                + shellQuote(pattern)
                + " || " + iptables + " -S " + shellQuote(CHAIN_FILTER)
                + " 2>/dev/null | grep -q -- " + shellQuote(pattern) + " )";
    }

    private static String buildIptablesUid0FilterAcceptCheck(String iptables) {
        List<String> checks = new ArrayList<>();
        for (Integer port : dnsUpstreamPortsForFilterFallback()) {
            checks.add(buildIptablesUid0FilterAcceptRuleCheck(iptables, "udp", port));
            checks.add(buildIptablesUid0FilterAcceptRuleCheck(iptables, "tcp", port));
        }
        return "( " + joinShellChecks(checks) + " )";
    }

    private static String buildIptablesUid0FilterAcceptRuleCheck(String iptables,
                                                                 String protocol,
                                                                 int port) {
        String lineCheck = "grep -- '--uid-owner 0' | grep -- '-p " + protocol
                + "' | grep -- '--dport " + port + "' | grep -q -- '-j ACCEPT'";
        return "( " + iptables + " -S OUTPUT 2>/dev/null | " + lineCheck
                + " || " + iptables + " -S " + shellQuote(CHAIN_FILTER)
                + " 2>/dev/null | " + lineCheck + " )";
    }

    private static String buildIptablesUid0ReturnCheck(String iptables, String chain) {
        String pattern = "-m owner .*--uid-owner 0.*-j RETURN";
        return iptables + " -t nat -S " + shellQuote(chain)
                + " 2>/dev/null | grep -q -- " + shellQuote(pattern);
    }

    private static String buildIptablesRedirectTargetCheck(String iptables, String chain,
                                                           String protocol, int port) {
        String pattern = "-p " + protocol + " .*--dport 53.*-j REDIRECT.*--to-ports " + port;
        return iptables + " -t nat -S " + shellQuote(chain)
                + " 2>/dev/null | grep -q -- " + shellQuote(pattern);
    }

    private static String buildNftRedirectHealthyCondition(String family, String table, int port,
                                                           String iptables) {
        List<String> checks = new ArrayList<>();
        checks.add("command -v nft >/dev/null 2>&1");
        checks.add("nft list table " + shellQuote(family) + " " + shellQuote(table)
                + " >/dev/null 2>&1");
        checks.add("( ( " + buildNftDaemonMarkReturnCheck(family, table)
                + " && " + buildIptablesDaemonMarkFilterAcceptCheck(iptables)
                + " ) || ( " + buildNftUid0ReturnCheck(family, table)
                + " && " + buildIptablesUid0FilterAcceptCheck(iptables) + " ) )");
        checks.add(buildNftRedirectCheck(family, table, NFT_OUTPUT, "udp", port));
        checks.add(buildNftRedirectCheck(family, table, NFT_OUTPUT, "tcp", port));
        if (preroutingRedirectExpected()) {
            checks.add(buildNftRedirectCheck(family, table, NFT_PREROUTING, "udp", port));
            checks.add(buildNftRedirectCheck(family, table, NFT_PREROUTING, "tcp", port));
        }
        return joinShellChecks(checks);
    }

    private static String buildNftRedirectCheck(String family, String table, String chain,
                                                String protocol, int port) {
        String pattern = protocol + " dport 53.*redirect to :" + port;
        return "nft list chain " + shellQuote(family) + " " + shellQuote(table)
                + " " + shellQuote(chain)
                + " 2>/dev/null | grep -q -- " + shellQuote(pattern);
    }

    private static String buildNftDaemonMarkReturnCheck(String family, String table) {
        String pattern = "meta mark .*return";
        return "nft list chain " + shellQuote(family) + " " + shellQuote(table)
                + " " + shellQuote(NFT_OUTPUT)
                + " 2>/dev/null | grep -q -- " + shellQuote(pattern);
    }

    private static String buildNftUid0ReturnCheck(String family, String table) {
        String pattern = "meta skuid 0.*return";
        return "nft list chain " + shellQuote(family) + " " + shellQuote(table)
                + " " + shellQuote(NFT_OUTPUT)
                + " 2>/dev/null | grep -q -- " + shellQuote(pattern);
    }

    private static String joinShellChecks(List<String> checks) {
        StringBuilder command = new StringBuilder();
        for (String check : checks) {
            if (check == null || check.trim().isEmpty()) {
                continue;
            }
            if (command.length() > 0) {
                command.append(" && ");
            }
            command.append(check);
        }
        return command.length() == 0 ? "false" : command.toString();
    }

    private static String buildNftTableStatusCommand(String key, String family, String table) {
        return "if command -v nft >/dev/null 2>&1 && nft list table "
                + shellQuote(family) + " " + shellQuote(table)
                + " >/dev/null 2>&1; then echo " + key + "=1; else echo "
                + key + "=0; fi";
    }

    private static String buildNftDaemonMarkReturnStatusCommand(String key, String family,
                                                                String table) {
        return "if command -v nft >/dev/null 2>&1 && "
                + buildNftDaemonMarkReturnCheck(family, table)
                + "; then echo " + key + "=1; else echo " + key + "=0; fi";
    }

    private static String buildNftUid0ReturnStatusCommand(String key, String family,
                                                          String table) {
        return "if command -v nft >/dev/null 2>&1 && "
                + buildNftUid0ReturnCheck(family, table)
                + "; then echo " + key + "=1; else echo " + key + "=0; fi";
    }

    private static String buildNftRedirectStatusCommand(String key, String family, String table,
                                                        String chain, String protocol, int port) {
        String pattern = protocol + " dport 53.*redirect to :" + port;
        return "if command -v nft >/dev/null 2>&1 && nft list chain "
                + shellQuote(family) + " " + shellQuote(table) + " " + shellQuote(chain)
                + " 2>/dev/null | grep -q -- " + shellQuote(pattern)
                + "; then echo " + key + "=1; else echo " + key + "=0; fi";
    }

    private static String redirectFamilyStatus(Map<String, String> values, String prefix) {
        boolean nftTable = "1".equals(values.get(prefix + "_nft_table"));
        int hookScore = redirectFamilyHookScore(values, prefix);
        int targetScore = redirectFamilyTargetScore(values, prefix);
        int nftInstalled = redirectFamilyNftScore(values, prefix);
        int targetExpected = expectedRedirectTargetScore();
        int nftExpected = expectedNftRedirectScore();
        boolean iptablesInstalled = hookScore >= expectedRedirectHookScore()
                && targetScore >= targetExpected
                && redirectFamilyIptablesDaemonPathReady(values, prefix);
        boolean nftReady = nftInstalled >= nftExpected && redirectFamilyNftDaemonPathReady(values, prefix);
        String suffix = redirectFamilyUsesUidFallback(values, prefix) ? " (UID fallback)" : "";
        if (!preroutingRedirectExpected()) {
            suffix += " (UID-scoped app-owned capture)";
        }
        String filterSuffix = redirectFamilyMissingDaemonFilterBypass(values, prefix)
                ? " (daemon filter bypass missing)" : "";
        if (nftReady && iptablesInstalled) {
            return "installed (iptables+nft)" + suffix;
        }
        if (nftReady) {
            return "installed (nft)" + suffix;
        }
        if (iptablesInstalled) {
            return "installed" + suffix;
        }
        if (hookScore > 0 || targetScore > 0 || nftInstalled > 0 || nftTable) {
            return "partial" + filterSuffix;
        }
        return "missing";
    }

    private static boolean redirectFamilyHealthy(Map<String, String> values, String prefix) {
        return (redirectFamilyHookScore(values, prefix) >= expectedRedirectHookScore()
                && redirectFamilyTargetScore(values, prefix) >= expectedRedirectTargetScore()
                && redirectFamilyIptablesDaemonPathReady(values, prefix))
                || (redirectFamilyNftScore(values, prefix) >= expectedNftRedirectScore()
                && redirectFamilyNftDaemonPathReady(values, prefix));
    }

    private static int expectedRedirectHookScore() {
        return preroutingRedirectExpected() ? 6 : 3;
    }

    private static int expectedRedirectTargetScore() {
        return preroutingRedirectExpected() ? 4 : 2;
    }

    private static int expectedNftRedirectScore() {
        return preroutingRedirectExpected() ? 4 : 2;
    }

    private static boolean preroutingRedirectExpected() {
        return parseUidList(G.dnsHijackCaptureUids()).isEmpty();
    }

    private static boolean redirectFamilyIptablesRecursionGuard(Map<String, String> values,
                                                                String prefix) {
        return "1".equals(values.get(prefix + "_output_daemon_mark_return"))
                || "1".equals(values.get(prefix + "_output_uid0_return"));
    }

    private static boolean redirectFamilyIptablesDaemonPathReady(Map<String, String> values,
                                                                 String prefix) {
        return ("1".equals(values.get(prefix + "_output_daemon_mark_return"))
                && redirectFamilyDaemonFilterBypass(values, prefix))
                || ("1".equals(values.get(prefix + "_output_uid0_return"))
                && redirectFamilyUid0FilterBypass(values, prefix));
    }

    private static boolean redirectFamilyNftRecursionGuard(Map<String, String> values,
                                                           String prefix) {
        return "1".equals(values.get(prefix + "_nft_output_daemon_mark_return"))
                || "1".equals(values.get(prefix + "_nft_output_uid0_return"));
    }

    private static boolean redirectFamilyNftDaemonPathReady(Map<String, String> values,
                                                            String prefix) {
        return ("1".equals(values.get(prefix + "_nft_output_daemon_mark_return"))
                && redirectFamilyDaemonFilterBypass(values, prefix))
                || ("1".equals(values.get(prefix + "_nft_output_uid0_return"))
                && redirectFamilyUid0FilterBypass(values, prefix));
    }

    private static boolean redirectFamilyUsesUidFallback(Map<String, String> values, String prefix) {
        return "1".equals(values.get(prefix + "_output_uid0_return"))
                || "1".equals(values.get(prefix + "_nft_output_uid0_return"));
    }

    private static boolean redirectFamilyMissingDaemonFilterBypass(Map<String, String> values,
                                                                   String prefix) {
        boolean markGuard = "1".equals(values.get(prefix + "_output_daemon_mark_return"))
                || "1".equals(values.get(prefix + "_nft_output_daemon_mark_return"));
        boolean uidGuard = "1".equals(values.get(prefix + "_output_uid0_return"))
                || "1".equals(values.get(prefix + "_nft_output_uid0_return"));
        return (markGuard && !redirectFamilyDaemonFilterBypass(values, prefix))
                || (uidGuard && !redirectFamilyUid0FilterBypass(values, prefix));
    }

    private static boolean redirectFamilyDaemonFilterBypass(Map<String, String> values,
                                                            String prefix) {
        return "1".equals(values.get(prefix + "_filter_daemon_mark_accept"));
    }

    private static boolean redirectFamilyUid0FilterBypass(Map<String, String> values,
                                                          String prefix) {
        return "1".equals(values.get(prefix + "_filter_uid0_dns_accept"));
    }

    private static int redirectFamilyHookScore(Map<String, String> values, String prefix) {
        String[] keys = new String[] {
                "_chain",
                "_pre_chain",
                "_output_udp",
                "_output_tcp",
                "_prerouting_udp",
                "_prerouting_tcp"
        };
        int score = 0;
        for (String suffix : keys) {
            if ("1".equals(values.get(prefix + suffix))) {
                score++;
            }
        }
        return score;
    }

    private static int redirectFamilyTargetScore(Map<String, String> values, String prefix) {
        String[] keys = new String[] {
                "_chain_udp_redirect",
                "_chain_tcp_redirect",
                "_pre_chain_udp_redirect",
                "_pre_chain_tcp_redirect"
        };
        int score = 0;
        for (String suffix : keys) {
            if ("1".equals(values.get(prefix + suffix))) {
                score++;
            }
        }
        return score;
    }

    private static int redirectFamilyNftScore(Map<String, String> values, String prefix) {
        String[] keys = new String[] {
                "_nft_output_udp",
                "_nft_output_tcp",
                "_nft_prerouting_udp",
                "_nft_prerouting_tcp"
        };
        int score = 0;
        for (String suffix : keys) {
            if ("1".equals(values.get(prefix + suffix))) {
                score++;
            }
        }
        return score;
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

    private static void runLifecycleCommands(Context context, List<String> commands,
                                             String queuedMessage, String successMessage,
                                             String failureMessage, RootCommand.Callback callback) {
        ApplicationErrorLog.add(context, queuedMessage);
        new RootCommand()
                .setLogging(true)
                .setReopenShell(true)
                .setFailureToast(R.string.error_apply)
                .setCallback(new RootCommand.Callback() {
                    @Override
                    public void cbFunc(RootCommand state) {
                        if (state.exitCode == 0) {
                            ApplicationErrorLog.add(context, successMessage);
                        } else {
                            ApplicationErrorLog.add(context,
                                    failureMessage + rootFailureSuffix(state));
                        }
                        syncServiceLogsToAppLog(context);
                        if (callback != null) {
                            callback.cbFunc(state);
                        }
                    }
                })
                .run(context.getApplicationContext(), commands);
    }

    private static String rootFailureSuffix(RootCommand state) {
        if (state == null) {
            return "";
        }
        StringBuilder detail = new StringBuilder();
        if (state.lastCommand != null && !state.lastCommand.trim().isEmpty()) {
            detail.append(": command=").append(state.lastCommand.trim());
        }
        String output = state.lastCommandResult == null
                ? ""
                : state.lastCommandResult.toString().trim().replace('\n', ' ');
        if (!output.isEmpty()) {
            if (output.length() > 240) {
                output = output.substring(0, 240);
            }
            detail.append(" output=").append(output);
        }
        return detail.toString();
    }

    private static String queryControl(Context context, String command) {
        return queryControl(context, command, null);
    }

    private static String queryControl(Context context, String command, String overrideToken) {
        return queryControl(context, command, overrideToken, 1500);
    }

    private static String queryControl(Context context, String command, int timeoutMs) {
        return queryControl(context, command, null, timeoutMs);
    }

    private static String queryControl(Context context, String command, String overrideToken,
                                       int timeoutMs) {
        File socketFile = new File(workDir(context), SOCKET);
        if (!socketFile.exists()) {
            return "control socket missing\n";
        }
        String token = overrideToken == null ? controlToken(context) : overrideToken;
        if (token.isEmpty()) {
            return "control token unavailable\n";
        }
        try (LocalSocket socket = new LocalSocket()) {
            socket.setSoTimeout(timeoutMs);
            socket.connect(new LocalSocketAddress(socketFile.getAbsolutePath(), LocalSocketAddress.Namespace.FILESYSTEM));
            OutputStream output = socket.getOutputStream();
            output.write(("token " + token + "\n" + command + "\n").getBytes(StandardCharsets.UTF_8));
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

    private static String buildInvalidControlToken(Context context) {
        String zero = "0000000000000000000000000000000000000000000000000000000000000000";
        String actual = controlToken(context);
        if (!zero.equals(actual)) {
            return zero;
        }
        return "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    }

    private static void appendSelfTestValue(StringBuilder out, Map<String, String> values,
                                            String key) {
        if (out == null || values == null || key == null) {
            return;
        }
        String value = values.get(key);
        out.append(key).append('=').append(value == null ? "missing" : value).append('\n');
    }

    private static String controlToken(Context context) {
        if (context == null) {
            return "";
        }
        File tokenFile = new File(workDir(context), CONTROL_TOKEN);
        String existing = readSmallFileValue(tokenFile, "").trim();
        if (isValidControlToken(existing)) {
            setOwnerOnly(tokenFile);
            return existing;
        }
        byte[] tokenBytes = new byte[32];
        new SecureRandom().nextBytes(tokenBytes);
        String generated = toHex(tokenBytes);
        try {
            writeText(tokenFile, generated + "\n");
            setOwnerOnly(tokenFile);
            return generated;
        } catch (IOException | RuntimeException e) {
            ApplicationErrorLog.add(context, "DNS control token could not be written: "
                    + e.getMessage());
            return "";
        }
    }

    private static void setOwnerOnly(File file) {
        if (file == null) {
            return;
        }
        file.setReadable(false, false);
        file.setWritable(false, false);
        file.setExecutable(false, false);
        file.setReadable(true, true);
        file.setWritable(true, true);
    }

    private static boolean isValidControlToken(String token) {
        if (token == null || token.length() < 32 || token.length() > 96) {
            return false;
        }
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            boolean hex = (c >= '0' && c <= '9')
                    || (c >= 'a' && c <= 'f')
                    || (c >= 'A' && c <= 'F');
            if (!hex) {
                return false;
            }
        }
        return true;
    }

    private static String toHex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        char[] alphabet = "0123456789abcdef".toCharArray();
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xff;
            out[i * 2] = alphabet[value >>> 4];
            out[i * 2 + 1] = alphabet[value & 0x0f];
        }
        return new String(out);
    }

    private static String compactControlResponse(String response) {
        String compact = response == null ? "" : response.trim().replace('\n', ' ');
        if (compact.length() > 240) {
            compact = compact.substring(0, 240);
        }
        return compact.isEmpty() ? "empty response" : compact;
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

    private static String cacheHitRate(long ppm, long hits, long misses) {
        if (ppm >= 0L) {
            return String.format(Locale.US, "%.1f%%", ppm / 10000.0d);
        }
        long total = hits + misses;
        if (total <= 0L) {
            return "0%";
        }
        return String.format(Locale.US, "%.1f%%", (hits * 100.0d) / total);
    }

    private static String formatMillis(long value) {
        return value < 0L ? "n/a" : value + "ms";
    }

    private static String formatKilobytes(long value) {
        if (value < 0L) {
            return "n/a";
        }
        if (value < 1024L) {
            return value + " KB";
        }
        return String.format(Locale.US, "%.1f MB", value / 1024.0d);
    }

    private static String formatDuration(long seconds) {
        if (seconds <= 0L) {
            return "0s";
        }
        long days = seconds / 86400L;
        seconds %= 86400L;
        long hours = seconds / 3600L;
        seconds %= 3600L;
        long minutes = seconds / 60L;
        seconds %= 60L;
        if (days > 0L) {
            return days + "d " + hours + "h";
        }
        if (hours > 0L) {
            return hours + "h " + minutes + "m";
        }
        if (minutes > 0L) {
            return minutes + "m " + seconds + "s";
        }
        return seconds + "s";
    }

    private static long sumDashboardRuleCounts(Map<String, String> preferred,
                                               Map<String, String> fallback) {
        String[] keys = new String[] {
                "rules_exact_allow",
                "rules_suffix_allow",
                "rules_exact_block",
                "rules_suffix_block",
                "rules_app_exact_allow",
                "rules_app_exact_block",
                "rules_app_suffix_allow",
                "rules_app_suffix_block",
                "rules_network_allow",
                "rules_network_block",
                "rules_regex_allow",
                "rules_regex_block",
                "rules_temp_allow",
                "rules_temp_block"
        };
        long total = 0L;
        for (String key : keys) {
            total += parseLong(firstValue(preferred, fallback, key), 0L);
        }
        return total;
    }

    private static String upstreamRuntimeSummary(Map<String, String> preferred,
                                                 Map<String, String> fallback) {
        List<String> summaries = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            String raw = firstValue(preferred, fallback, "upstream_runtime[" + i + "]");
            if (!raw.isEmpty()) {
                summaries.add(formatUpstreamRuntime(raw));
            }
        }
        if (summaries.isEmpty()) {
            return "runtime unavailable";
        }
        return joinWithSeparator(summaries, " | ");
    }

    private static String formatUpstreamRuntime(String raw) {
        String endpoint = "";
        String protocol = tokenValue(raw, "protocol", "");
        String requests = tokenValue(raw, "requests", "0");
        String successes = tokenValue(raw, "successes", "0");
        String failures = tokenValue(raw, "failures", "0");
        String averageLatency = tokenValue(raw, "avg_latency_ms", "n/a");
        String backoffRemaining = tokenValue(raw, "backoff_remaining", "0");
        String[] parts = raw.trim().split("\\s+");
        for (String part : parts) {
            if (part.startsWith("upstream=")) {
                endpoint = part.substring("upstream=".length());
                break;
            }
            if (!part.contains("=") && endpoint.isEmpty()) {
                endpoint = part;
            }
        }
        if (endpoint.isEmpty()) {
            endpoint = "upstream";
        }
        if (protocol.isEmpty()) {
            protocol = "auto";
        }
        String backoff = "0".equals(backoffRemaining)
                ? ""
                : " backoff=" + backoffRemaining + "s";
        return endpoint + " " + protocol
                + " ok=" + successes + "/" + requests
                + " fail=" + failures
                + " avg=" + formatRuntimeLatency(averageLatency)
                + backoff;
    }

    private static String formatRuntimeLatency(String value) {
        return "n/a".equals(value) ? value : value + "ms";
    }

    private static String tokenValue(String raw, String key, String fallback) {
        if (raw == null || key == null) {
            return fallback;
        }
        String prefix = key + "=";
        String[] parts = raw.trim().split("\\s+");
        for (String part : parts) {
            if (part.startsWith(prefix)) {
                String value = part.substring(prefix.length()).trim();
                return value.isEmpty() ? fallback : value;
            }
        }
        return fallback;
    }

    private static String joinWithSeparator(List<String> values, String separator) {
        StringBuilder out = new StringBuilder();
        for (String value : values) {
            if (value == null || value.trim().isEmpty()) {
                continue;
            }
            if (out.length() > 0) {
                out.append(separator);
            }
            out.append(value.trim());
        }
        return out.toString();
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
        out.append("dnssec_request=").append(G.dnsHijackDnssecRequest() ? 1 : 0).append('\n');
        out.append("dnssec_auth_required=")
                .append(G.dnsHijackDnssecAuthRequired() ? 1 : 0).append('\n');
        out.append("probe_dnssec=").append(dnssecProbeRequired() ? 1 : 0).append('\n');
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
            byte[] response = new byte[dnssecProbeRequired() ? 4096 : 512];
            DatagramPacket reply = new DatagramPacket(response, response.length);
            socket.receive(reply);
            int bytes = reply.getLength();
            if (G.dnsHijackDnssecAuthRequired() && !responseAuthenticated(response, bytes)) {
                return new ProbeResult("unauthenticated", bytes, bytes >= 4 ? response[3] & 0x0f : -1);
            }
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
            if (read == expected && G.dnsHijackDnssecAuthRequired()
                    && !responseAuthenticated(response, read)) {
                return new ProbeResult("unauthenticated", read, read >= 4 ? response[3] & 0x0f : -1);
            }
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
        if (!dnssecProbeRequired()) {
            return query;
        }
        byte[] dnssecQuery = new byte[query.length + 11];
        System.arraycopy(query, 0, dnssecQuery, 0, query.length);
        dnssecQuery[10] = 0x00;
        dnssecQuery[11] = 0x01;
        int pos = query.length;
        dnssecQuery[pos++] = 0x00;
        dnssecQuery[pos++] = 0x00;
        dnssecQuery[pos++] = 0x29;
        dnssecQuery[pos++] = 0x10;
        dnssecQuery[pos++] = 0x00;
        dnssecQuery[pos++] = 0x00;
        dnssecQuery[pos++] = 0x00;
        dnssecQuery[pos++] = (byte) 0x80;
        dnssecQuery[pos++] = 0x00;
        dnssecQuery[pos++] = 0x00;
        dnssecQuery[pos] = 0x00;
        return dnssecQuery;
    }

    private static boolean dnssecProbeRequired() {
        return G.dnsHijackDnssecRequest() || G.dnsHijackDnssecAuthRequired();
    }

    private static boolean responseAuthenticated(byte[] response, int length) {
        return response != null && length >= 4 && (response[3] & 0x20) != 0;
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

    private static List<Integer> dnsUpstreamPortsForFilterFallback() {
        List<Integer> ports = new ArrayList<>();
        addUpstreamPorts(ports, G.dnsHijackUpstreams());
        String split = G.dnsHijackSplitUpstreams();
        if (split != null) {
            String[] lines = split.split("\\r?\\n");
            for (String line : lines) {
                String value = line == null ? "" : line.trim();
                int separator = findSplitSeparator(value);
                if (value.isEmpty() || value.startsWith("#") || separator <= 0) {
                    continue;
                }
                addUpstreamPorts(ports, value.substring(separator + 1));
            }
        }
        if (ports.isEmpty()) {
            ports.add(53);
        }
        return ports;
    }

    private static void addUpstreamPorts(List<Integer> ports, String raw) {
        for (UpstreamTarget target : parseUpstreamTargets(raw)) {
            addUpstreamPort(ports, target.port);
        }
    }

    private static void addUpstreamPort(List<Integer> ports, int port) {
        if (port > 0 && port <= 65535 && !ports.contains(port)) {
            ports.add(port);
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

    private static String readSmallFileValue(File file, String fallback) {
        if (file == null || !file.exists()) {
            return fallback;
        }
        try (FileInputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[256];
            int read = input.read(buffer);
            if (read <= 0) {
                return fallback;
            }
            String value = new String(buffer, 0, read, StandardCharsets.UTF_8).trim();
            return value.isEmpty() ? fallback : value;
        } catch (IOException e) {
            return fallback;
        }
    }

    private static String listenerLabel(boolean ready) {
        return ready ? "ready" : "missing";
    }

    private static String listenerFamilyLabel(boolean ready, boolean expected) {
        if (!expected) {
            return "disabled";
        }
        return listenerLabel(ready);
    }

    private static boolean listenerFamilyReady(Map<String, String> primaryValues,
                                               Map<String, String> fallbackValues,
                                               String familyKey, String aggregateKey) {
        String familyValue = firstValue(primaryValues, fallbackValues, familyKey);
        if (familyValue != null && !familyValue.trim().isEmpty()) {
            return "1".equals(familyValue);
        }
        return "1".equals(firstValue(primaryValues, fallbackValues, aggregateKey));
    }

    private static String normalizeSupervisorAction(String action) {
        if ("start".equals(action) || "stop".equals(action)
                || "restart".equals(action) || "reload".equals(action)
                || "status".equals(action)) {
            return action;
        }
        return null;
    }

    private static String normalizeDaemonMaintenanceAction(String action) {
        if ("flush_cache".equals(action)
                || "flush_logs".equals(action)
                || "clear_logs".equals(action)) {
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

    private static String joinLabels(List<String> labels) {
        StringBuilder joined = new StringBuilder();
        for (String label : labels) {
            if (label == null || label.trim().isEmpty()) {
                continue;
            }
            if (joined.length() > 0) {
                joined.append(", ");
            }
            joined.append(label.trim());
        }
        return joined.toString();
    }

    private static int parseQueryUid(QueryEntry entry) {
        if (entry == null || entry.uid == null) {
            return -1;
        }
        try {
            return Integer.parseInt(entry.uid.trim());
        } catch (NumberFormatException e) {
            return -1;
        }
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
                    + " bypass_interfaces=" + bypassInterfaceCount
                    + (captureCount > 0
                    ? " prerouting_capture=disabled_uid_scope"
                    : ""));
        }
        if (captureCount > 0) {
            ApplicationErrorLog.add(context, prefix
                    + ": UID capture scope active; PREROUTING capture disabled because forwarded packets do not expose app UID");
            ApplicationErrorLog.add(context, prefix
                    + ": Android system resolver packets may use a system UID; leave DNS capture UIDs empty for full Android resolver capture");
        }
    }

    private static boolean appendOutputPolicyRules(List<String> commands, String appendCommand, int port) {
        return appendOutputPolicyRules(commands, appendCommand, port, false);
    }

    private static boolean appendOutputPolicyRules(List<String> commands, String appendCommand,
                                                   int port, boolean tolerant) {
        List<Integer> bypassUids = parseUidList(G.dnsHijackBypassUids());
        List<Integer> captureUids = parseUidList(G.dnsHijackCaptureUids());
        List<String> bypassInterfaces = parseInterfaceList(G.dnsHijackBypassInterfaces());
        List<String> captureInterfaces = parseInterfaceList(G.dnsHijackCaptureInterfaces());
        for (String iface : bypassInterfaces) {
            appendIptablesPolicyCommand(commands, appendCommand + " -o " + iface + " -j RETURN",
                    tolerant);
        }
        for (Integer uid : bypassUids) {
            appendIptablesPolicyCommand(commands,
                    appendCommand + " -m owner --uid-owner " + uid + " -j RETURN", tolerant);
        }
        if (captureUids.isEmpty() && captureInterfaces.isEmpty()) {
            return false;
        }
        if (captureUids.isEmpty()) {
            for (String iface : captureInterfaces) {
                appendOutputRedirect(commands, appendCommand, port, null, iface, tolerant);
            }
        } else if (captureInterfaces.isEmpty()) {
            for (Integer uid : captureUids) {
                if (!bypassUids.contains(uid)) {
                    appendOutputRedirect(commands, appendCommand, port, uid, null, tolerant);
                }
            }
        } else {
            for (String iface : captureInterfaces) {
                if (bypassInterfaces.contains(iface)) {
                    continue;
                }
                for (Integer uid : captureUids) {
                    if (!bypassUids.contains(uid)) {
                        appendOutputRedirect(commands, appendCommand, port, uid, iface, tolerant);
                    }
                }
            }
        }
        appendIptablesPolicyCommand(commands, appendCommand + " -j RETURN", tolerant);
        return true;
    }

    private static void appendOutputRedirect(List<String> commands, String appendCommand,
                                             int port, Integer uid, String iface) {
        appendOutputRedirect(commands, appendCommand, port, uid, iface, false);
    }

    private static void appendOutputRedirect(List<String> commands, String appendCommand,
                                             int port, Integer uid, String iface,
                                             boolean tolerant) {
        String matcher = "";
        if (iface != null) {
            matcher += " -o " + iface;
        }
        if (uid != null) {
            matcher += " -m owner --uid-owner " + uid;
        }
        appendIptablesPolicyCommand(commands,
                appendCommand + matcher + " -p udp --dport 53 -j REDIRECT --to-ports " + port,
                tolerant);
        appendIptablesPolicyCommand(commands,
                appendCommand + matcher + " -p tcp --dport 53 -j REDIRECT --to-ports " + port,
                tolerant);
    }

    private static boolean appendPreroutingPolicyRules(List<String> commands, String appendCommand, int port) {
        return appendPreroutingPolicyRules(commands, appendCommand, port, false);
    }

    private static boolean appendPreroutingPolicyRules(List<String> commands, String appendCommand,
                                                       int port, boolean tolerant) {
        List<Integer> captureUids = parseUidList(G.dnsHijackCaptureUids());
        List<String> bypassInterfaces = parseInterfaceList(G.dnsHijackBypassInterfaces());
        List<String> captureInterfaces = parseInterfaceList(G.dnsHijackCaptureInterfaces());
        for (String iface : bypassInterfaces) {
            appendIptablesPolicyCommand(commands, appendCommand + " -i " + iface + " -j RETURN",
                    tolerant);
        }
        if (!captureUids.isEmpty()) {
            appendIptablesPolicyCommand(commands, appendCommand + " -j RETURN", tolerant);
            return true;
        }
        if (captureInterfaces.isEmpty()) {
            return false;
        }
        for (String iface : captureInterfaces) {
            if (bypassInterfaces.contains(iface)) {
                continue;
            }
            appendIptablesPolicyCommand(commands,
                    appendCommand + " -i " + iface
                            + " -p udp --dport 53 -j REDIRECT --to-ports " + port,
                    tolerant);
            appendIptablesPolicyCommand(commands,
                    appendCommand + " -i " + iface
                            + " -p tcp --dport 53 -j REDIRECT --to-ports " + port,
                    tolerant);
        }
        appendIptablesPolicyCommand(commands, appendCommand + " -j RETURN", tolerant);
        return true;
    }

    private static void appendIptablesPolicyCommand(List<String> commands, String command,
                                                    boolean tolerant) {
        commands.add(tolerant ? command + " >/dev/null 2>&1 || true" : command);
    }

    private static String buildNftFallbackRestoreCommand(Context context, boolean ipv6) {
        String iptables = shellQuote(Api.getBinaryPath(context, ipv6));
        String chain = ipv6 ? CHAIN_V6 : CHAIN_V4;
        String preChain = ipv6 ? CHAIN_V6_PRE : CHAIN_V4_PRE;
        String family = ipv6 ? "ip6" : "ip";
        String table = ipv6 ? NFT_TABLE_V6 : NFT_TABLE_V4;
        int port = G.dnsHijackPort(DEFAULT_PORT);
        String markStatus = shellQuote(new File(workDir(context), MARK_STATUS).getAbsolutePath());
        return "if command -v nft >/dev/null 2>&1; then if ! ( "
                + buildIptablesRedirectHealthyCondition(iptables, chain, preChain, port)
                + " ); then " + buildNftRuntimeRestoreCommands(family, table,
                String.valueOf(port), markStatus)
                + "else nft delete table " + family + " " + table
                + " >/dev/null 2>&1 || true; fi; fi; true";
    }

    private static String buildNftPurgeCommand() {
        return "if command -v nft >/dev/null 2>&1; then "
                + buildNftFamilyPurgeCommand(false)
                + buildNftFamilyPurgeCommand(true)
                + "fi; true";
    }

    private static String buildNftFamilyPurgeCommand(boolean ipv6) {
        String family = ipv6 ? "ip6" : "ip";
        String table = ipv6 ? NFT_TABLE_V6 : NFT_TABLE_V4;
        return "nft delete table " + family + " " + table + " >/dev/null 2>&1 || true; ";
    }

    private static String buildNftRuntimeRestoreCommands(String family, String table,
                                                         String portValue,
                                                         String markStatusShellPath) {
        return "if [ -r " + markStatusShellPath + " ] && grep -q '^supported ' "
                + markStatusShellPath + "; then "
                + buildNftRestoreCommands(family, table, portValue, false)
                + "else echo 'DNS nftables fallback using UID 0 daemon bypass because daemon mark is unavailable'; "
                + buildNftRestoreCommands(family, table, portValue, true)
                + "fi; ";
    }

    private static String buildNftRestoreCommands(String family, String table, String portValue,
                                                  boolean uid0DaemonFallback) {
        List<String> nftCommands = new ArrayList<>();
        appendNftCommand(nftCommands, "add table " + family + " " + table);
        appendNftCommand(nftCommands, "add chain " + family + " " + table + " " + NFT_OUTPUT
                + " { type nat hook output priority dstnat; policy accept; }");
        appendNftCommand(nftCommands, "add chain " + family + " " + table + " " + NFT_PREROUTING
                + " { type nat hook prerouting priority dstnat; policy accept; }");
        appendNftOutputRules(nftCommands, family, table, portValue, uid0DaemonFallback);
        appendNftPreroutingRules(nftCommands, family, table, portValue);

        StringBuilder command = new StringBuilder();
        command.append("nft delete table ").append(family).append(' ').append(table)
                .append(" >/dev/null 2>&1 || true; ");
        appendNftScriptCommand(command, nftCommands);
        command.append("true; ");
        return command.toString();
    }

    private static void appendNftCommand(List<String> commands, String nftArgs) {
        commands.add(nftArgs);
    }

    private static void appendNftScriptCommand(StringBuilder command, List<String> nftCommands) {
        // nft chain definitions include shell-significant braces and semicolons, so feed nft a script.
        command.append("printf '%s\\n'");
        for (String nftCommand : nftCommands) {
            command.append(' ').append(shellQuote(nftCommand));
        }
        command.append(" | nft -f - && ");
    }

    private static void appendNftOutputRules(List<String> command, String family,
                                             String table, String portValue,
                                             boolean uid0DaemonFallback) {
        List<Integer> bypassUids = parseUidList(G.dnsHijackBypassUids());
        List<Integer> captureUids = parseUidList(G.dnsHijackCaptureUids());
        List<String> bypassInterfaces = parseInterfaceList(G.dnsHijackBypassInterfaces());
        List<String> captureInterfaces = parseInterfaceList(G.dnsHijackCaptureInterfaces());
        appendNftRule(command, family, table, NFT_OUTPUT, "oifname " + nftString("lo") + " return");
        if (uid0DaemonFallback) {
            appendNftRule(command, family, table, NFT_OUTPUT, "meta skuid 0 return");
        } else {
            appendNftRule(command, family, table, NFT_OUTPUT,
                    "meta mark " + DAEMON_SOCKET_MARK + " return");
        }
        for (String iface : bypassInterfaces) {
            appendNftRule(command, family, table, NFT_OUTPUT,
                    "oifname " + nftString(nftInterfacePattern(iface)) + " return");
        }
        for (Integer uid : bypassUids) {
            appendNftRule(command, family, table, NFT_OUTPUT, "meta skuid " + uid + " return");
        }
        if (captureUids.isEmpty() && captureInterfaces.isEmpty()) {
            appendNftRedirect(command, family, table, NFT_OUTPUT, "", portValue);
            return;
        }
        if (captureUids.isEmpty()) {
            for (String iface : captureInterfaces) {
                appendNftRedirect(command, family, table, NFT_OUTPUT,
                        "oifname " + nftString(nftInterfacePattern(iface)), portValue);
            }
        } else if (captureInterfaces.isEmpty()) {
            for (Integer uid : captureUids) {
                if (!bypassUids.contains(uid)) {
                    appendNftRedirect(command, family, table, NFT_OUTPUT,
                            "meta skuid " + uid, portValue);
                }
            }
        } else {
            for (String iface : captureInterfaces) {
                if (bypassInterfaces.contains(iface)) {
                    continue;
                }
                for (Integer uid : captureUids) {
                    if (!bypassUids.contains(uid)) {
                        appendNftRedirect(command, family, table, NFT_OUTPUT,
                                "oifname " + nftString(nftInterfacePattern(iface))
                                        + " meta skuid " + uid, portValue);
                    }
                }
            }
        }
    }

    private static void appendNftPreroutingRules(List<String> command, String family,
                                                 String table, String portValue) {
        List<Integer> captureUids = parseUidList(G.dnsHijackCaptureUids());
        List<String> bypassInterfaces = parseInterfaceList(G.dnsHijackBypassInterfaces());
        List<String> captureInterfaces = parseInterfaceList(G.dnsHijackCaptureInterfaces());
        appendNftRule(command, family, table, NFT_PREROUTING,
                "iifname " + nftString("lo") + " return");
        for (String iface : bypassInterfaces) {
            appendNftRule(command, family, table, NFT_PREROUTING,
                    "iifname " + nftString(nftInterfacePattern(iface)) + " return");
        }
        if (!captureUids.isEmpty()) {
            appendNftRule(command, family, table, NFT_PREROUTING, "return");
            return;
        }
        if (captureInterfaces.isEmpty()) {
            appendNftRedirect(command, family, table, NFT_PREROUTING, "", portValue);
            return;
        }
        for (String iface : captureInterfaces) {
            if (bypassInterfaces.contains(iface)) {
                continue;
            }
            appendNftRedirect(command, family, table, NFT_PREROUTING,
                    "iifname " + nftString(nftInterfacePattern(iface)), portValue);
        }
    }

    private static void appendNftRedirect(List<String> command, String family, String table,
                                          String chain, String matcher, String portValue) {
        String prefix = matcher == null || matcher.isEmpty() ? "" : matcher + " ";
        appendNftRule(command, family, table, chain,
                prefix + "udp dport 53 redirect to :" + portValue);
        appendNftRule(command, family, table, chain,
                prefix + "tcp dport 53 redirect to :" + portValue);
    }

    private static void appendNftRule(List<String> command, String family, String table,
                                      String chain, String rule) {
        appendNftCommand(command, "add rule " + family + " " + table + " " + chain + " " + rule);
    }

    private static String nftInterfacePattern(String iface) {
        return iface != null && iface.endsWith("+")
                ? iface.substring(0, iface.length() - 1) + "*"
                : iface;
    }

    private static String nftString(String value) {
        return "\"" + value + "\"";
    }

    private static String buildBootDaemonFilterBypass(String tool) {
        return "  " + tool + " -D OUTPUT -m mark --mark \"$DAEMON_MARK\" -j ACCEPT >/dev/null 2>&1 || true\n"
                + "  " + tool + " -D OUTPUT -j \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  " + tool + " -N \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  " + tool + " -F \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  if [ -r \"$MARK_STATUS\" ] && grep -q '^supported ' \"$MARK_STATUS\"; then\n"
                + "    " + tool + " -A \"$FILTER\" -m mark --mark \"$DAEMON_MARK\" -j ACCEPT >> \"$LOG\" 2>&1 || log_msg 'DNS daemon mark filter bypass install failed'\n"
                + "  else\n"
                + "    log_msg 'DNS daemon mark unavailable; allowing UID 0 DNS upstream fallback through filter'\n"
                + buildBootUid0FilterFallbackRules(tool)
                + "  fi\n"
                + "  if ! " + tool + " -I OUTPUT 1 -j \"$FILTER\" >> \"$LOG\" 2>&1; then\n"
                + "    log_msg 'DNS daemon filter bypass hook install failed; upstream DNS may need root allowed'\n"
                + "  fi\n";
    }

    private static String buildBootUid0FilterFallbackRules(String tool) {
        StringBuilder script = new StringBuilder();
        for (Integer port : dnsUpstreamPortsForFilterFallback()) {
            script.append("    ").append(tool)
                    .append(" -A \"$FILTER\" -m owner --uid-owner 0 -p udp --dport ")
                    .append(port)
                    .append(" -j ACCEPT >> \"$LOG\" 2>&1 || log_msg 'DNS UID 0 UDP filter fallback install failed for port ")
                    .append(port).append("'\n");
            script.append("    ").append(tool)
                    .append(" -A \"$FILTER\" -m owner --uid-owner 0 -p tcp --dport ")
                    .append(port)
                    .append(" -j ACCEPT >> \"$LOG\" 2>&1 || log_msg 'DNS UID 0 TCP filter fallback install failed for port ")
                    .append(port).append("'\n");
        }
        return script.toString();
    }

    private static String buildBootDaemonRecursionBypass(String tool, String chainVariable) {
        return "  if [ -r \"$MARK_STATUS\" ] && grep -q '^supported ' \"$MARK_STATUS\"; then\n"
                + "    if ! " + tool + " -t nat -A \"" + chainVariable
                + "\" -m mark --mark \"$DAEMON_MARK\" -j RETURN >> \"$LOG\" 2>&1; then\n"
                + "      log_msg 'DNS daemon mark matcher unavailable; falling back to UID 0 OUTPUT bypass'\n"
                + "      " + tool + " -t nat -A \"" + chainVariable
                + "\" -m owner --uid-owner 0 -j RETURN >> \"$LOG\" 2>&1\n"
                + "    fi\n"
                + "  else\n"
                + "    log_msg 'DNS daemon mark status unavailable; falling back to UID 0 OUTPUT bypass'\n"
                + "    " + tool + " -t nat -A \"" + chainVariable
                + "\" -m owner --uid-owner 0 -j RETURN >> \"$LOG\" 2>&1\n"
                + "  fi\n";
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
        List<Integer> captureUids = parseUidList(G.dnsHijackCaptureUids());
        List<String> bypassInterfaces = parseInterfaceList(G.dnsHijackBypassInterfaces());
        List<String> captureInterfaces = parseInterfaceList(G.dnsHijackCaptureInterfaces());
        for (String iface : bypassInterfaces) {
            script.append("  ").append(tool).append(" -t nat -A \"")
                    .append(chainVariable).append("\" -i ")
                    .append(iface).append(" -j RETURN >> \"$LOG\" 2>&1\n");
        }
        if (!captureUids.isEmpty()) {
            script.append("  ").append(tool).append(" -t nat -A \"")
                    .append(chainVariable).append("\" -j RETURN >> \"$LOG\" 2>&1\n");
            return script.toString();
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
        public final String source;
        public final String uid;

        private QueryEntry(long timestamp, String action, String domain, String latency,
                           String transport, String qtype, String result, String rule,
                           String upstream, String source, String uid) {
            this.timestamp = timestamp;
            this.action = action;
            this.domain = domain;
            this.latency = latency;
            this.transport = emptyFallback(transport, "unknown");
            this.qtype = qtypeName(emptyFallback(qtype, "0"));
            this.result = emptyFallback(result, action);
            this.rule = emptyFallback(rule, action);
            this.upstream = emptyFallback(upstream, "unknown");
            this.source = emptyFallback(source, "unknown");
            this.uid = emptyFallback(uid, "-1");
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
                        extras.get("upstream"), extras.get("source"),
                        extras.get("uid"));
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
                    + "  source=" + source
                    + "  uid=" + uid
                    + "  qtype=" + qtype
                    + "  result=" + result
                    + "  rule=" + rule
                    + "  upstream=" + upstream;
        }
    }

    public static final class DnsDashboardSnapshot {
        public final String statusLine;
        public final String detailLine;
        public final boolean enabled;
        public final boolean daemonRunning;
        public final boolean listenersReady;
        public final boolean upstreamProbeHealthy;
        public final boolean privateDnsMayBypass;
        public final boolean rootUidMayBypass;
        public final String powerLine;

        private DnsDashboardSnapshot(String statusLine, String detailLine, boolean enabled,
                                     boolean daemonRunning, boolean listenersReady,
                                     boolean upstreamProbeHealthy, boolean privateDnsMayBypass,
                                     boolean rootUidMayBypass, String powerLine) {
            this.statusLine = statusLine;
            this.detailLine = detailLine;
            this.enabled = enabled;
            this.daemonRunning = daemonRunning;
            this.listenersReady = listenersReady;
            this.upstreamProbeHealthy = upstreamProbeHealthy;
            this.privateDnsMayBypass = privateDnsMayBypass;
            this.rootUidMayBypass = rootUidMayBypass;
            this.powerLine = powerLine;
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
            } else if (value.contains("://")) {
                return null;
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
            host = host.trim().toLowerCase(Locale.US);
            if (host.isEmpty() || host.contains("/") || host.contains("\\")
                    || host.contains(" ") || host.contains("\t")) {
                return null;
            }
            return new UpstreamTarget(host, port, protocol);
        }

        private boolean hasLiteralHost() {
            return isIpv4Literal(host) || host.contains(":");
        }

        private String toConfigValue() {
            String prefix = "tcp".equals(protocol) ? "tcp://"
                    : "udp".equals(protocol) ? "udp://" : "";
            String formattedHost = host.contains(":") && !host.startsWith("[")
                    ? "[" + host + "]" : host;
            return prefix + formattedHost + ":" + port;
        }

        private static int parsePort(String raw, int fallback) {
            try {
                int parsed = Integer.parseInt(raw.trim());
                return parsed > 0 && parsed <= 65535 ? parsed : fallback;
            } catch (NumberFormatException e) {
                return fallback;
            }
        }

        private static boolean isIpv4Literal(String value) {
            if (value == null) {
                return false;
            }
            String[] parts = value.split("\\.");
            if (parts.length != 4) {
                return false;
            }
            for (String part : parts) {
                try {
                    int parsed = Integer.parseInt(part);
                    if (parsed < 0 || parsed > 255) {
                        return false;
                    }
                } catch (NumberFormatException e) {
                    return false;
                }
            }
            return true;
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
        commands.add("#LITERAL# " + buildInstallBootPersistenceCommand(workDir(context), false));
        ApplicationErrorLog.add(context,
                "DNS hijacker Magisk boot module install queued as best effort during rule apply");
    }

    private static String buildInstallBootPersistenceCommand(File moduleSourceDir) {
        return buildInstallBootPersistenceCommand(moduleSourceDir, true);
    }

    private static String buildInstallBootPersistenceCommand(File moduleSourceDir,
                                                             boolean required) {
        String source = shellQuote(moduleSourceDir.getAbsolutePath());
        String moduleDir = shellQuote(MAGISK_MODULE_DIR);
        return "SRC=" + source + "; "
                + "MOD=" + moduleDir + "; "
                + "if [ -d /data/adb/modules ]; then "
                + "if mkdir -p \"$MOD\" 2>/dev/null "
                + "&& cp \"$SRC/" + MAGISK_MODULE_PROP + "\" \"$MOD/" + MAGISK_MODULE_PROP + "\" 2>/dev/null "
                + "&& cp \"$SRC/" + MAGISK_SERVICE_SCRIPT + "\" \"$MOD/" + MAGISK_SERVICE_SCRIPT + "\" 2>/dev/null "
                + "&& cp \"$SRC/" + MAGISK_UNINSTALL_SCRIPT + "\" \"$MOD/" + MAGISK_UNINSTALL_SCRIPT + "\" 2>/dev/null "
                + "&& chmod 644 \"$MOD/" + MAGISK_MODULE_PROP + "\" 2>/dev/null "
                + "&& chmod 755 \"$MOD/" + MAGISK_SERVICE_SCRIPT + "\" \"$MOD/" + MAGISK_UNINSTALL_SCRIPT + "\" 2>/dev/null "
                + "&& rm -f \"$MOD/disable\" \"$MOD/remove\" 2>/dev/null "
                + "&& touch \"$MOD/update\" 2>/dev/null; then "
                + "echo 'DNS Magisk module installed at " + MAGISK_MODULE_DIR + "'; "
                + buildRemoveLegacyRootScriptsCommand()
                + " else echo 'DNS Magisk module install failed at " + MAGISK_MODULE_DIR + "'; "
                + (required ? "false" : "true") + "; fi; "
                + "else echo 'DNS Magisk module install failed: /data/adb/modules not found'; "
                + (required ? "false" : "true") + "; fi";
    }

    private static String buildRemoveBootPersistenceCommand() {
        return "MOD=" + shellQuote(MAGISK_MODULE_DIR) + "; "
                + "if [ -d \"$MOD\" ]; then "
                + "if [ -x \"$MOD/" + MAGISK_UNINSTALL_SCRIPT + "\" ]; then "
                + "\"$MOD/" + MAGISK_UNINSTALL_SCRIPT + "\" "
                + ">> /data/local/tmp/" + MAGISK_MODULE_LOG + " 2>&1 || true; fi; "
                + "if [ -f \"$MOD/" + MAGISK_MODULE_PROP + "\" ] "
                + "&& grep -q '^id=" + MAGISK_MODULE_ID + "$' \"$MOD/" + MAGISK_MODULE_PROP + "\"; then "
                + "rm -f \"$MOD/" + MAGISK_MODULE_PROP + "\" "
                + "\"$MOD/" + MAGISK_SERVICE_SCRIPT + "\" "
                + "\"$MOD/" + MAGISK_UNINSTALL_SCRIPT + "\" "
                + "\"$MOD/update\" 2>/dev/null || true; "
                + "rmdir \"$MOD\" 2>/dev/null || true; fi; "
                + "if [ -d \"$MOD\" ]; then "
                + "touch \"$MOD/disable\" \"$MOD/remove\" 2>/dev/null || true; "
                + "echo 'DNS Magisk module removal scheduled'; "
                + "else echo 'DNS Magisk module removed'; fi; "
                + "fi; "
                + buildRemoveLegacyRootScriptsCommand();
    }

    private static String buildRemoveLifecycleCleanupCommand() {
        return buildRemoveRootScriptCommand(CLEANUP_SCRIPT);
    }

    private static String buildRemoveLegacyRootScriptsCommand() {
        return buildRemoveRootScriptCommand(BOOT_SCRIPT) + "; "
                + buildRemoveRootScriptCommand(CLEANUP_SCRIPT);
    }

    private static String buildRemoveRootScriptCommand(String scriptName) {
        return "for FILE in /data/adb/service.d/" + scriptName
                + " /su/su.d/" + scriptName
                + " /system/su.d/" + scriptName
                + " /system/etc/init.d/" + scriptName
                + "; do [ -e \"$FILE\" ] && rm -f \"$FILE\" 2>/dev/null; done; true";
    }

    private static String buildRepairServiceEventLogFilesCommand(Context context) {
        File dir = workDir(context);
        StringBuilder command = new StringBuilder();
        command.append("DIR=").append(shellQuote(dir.getAbsolutePath())).append("; ");
        command.append("if [ -d \"$DIR\" ]; then ");
        command.append("chmod 700 \"$DIR\" 2>/dev/null || true; ");
        for (String logName : SERVICE_EVENT_LOGS) {
            command.append("LOG=\"$DIR/").append(logName).append("\"; ")
                    .append("touch \"$LOG\" 2>/dev/null || true; ")
                    .append("chmod 644 \"$LOG\" 2>/dev/null || true; ");
        }
        command.append("fi; true");
        return command.toString();
    }

    private static String buildSupervisorReadinessCheckCommand(Context context) {
        String supervisor = shellQuote(supervisorPath(context));
        return "STATUS=$(" + supervisor + " status 2>&1); "
                + "if echo \"$STATUS\" | grep -q '^readiness=ready$'; then true; else "
                + "echo 'DNS supervisor readiness check failed'; "
                + "echo \"$STATUS\"; false; fi";
    }

    private static void appendRemoveBootPersistenceCommand(List<String> commands) {
        commands.add("#LITERAL# " + buildRemoveBootPersistenceCommand());
    }

    private static void appendRemoveLifecycleCleanupCommand(List<String> commands) {
        commands.add("#LITERAL# " + buildRemoveLifecycleCleanupCommand());
    }

    private static List<String> buildRootRepairCommands(Context context) {
        List<String> commands = new ArrayList<>();
        commands.add(buildRepairServiceEventLogFilesCommand(context));
        appendLegacySupervisorStopCommand(context, commands, false);
        commands.add(shellQuote(supervisorPath(context)) + " restart");
        commands.add(buildSupervisorReadinessCheckCommand(context));
        logRedirectPolicy(context, "DNS redirect policy repair queued");
        appendRootRedirectRepairCommands(context, commands, false);
        if (G.enableIPv6()) {
            appendRootRedirectRepairCommands(context, commands, true);
        } else {
            appendDirectPurgeRules(context, commands, true);
            commands.add(buildNftFamilyPurgeCommand(true));
        }
        if (G.dnsHijackBootPersistence()) {
            commands.add(buildInstallBootPersistenceCommand(workDir(context), false));
            ApplicationErrorLog.add(context,
                    "DNS Magisk boot module install queued as best effort during DNS protection repair");
        } else {
            commands.add(buildRemoveBootPersistenceCommand());
        }
        return commands;
    }

    private static List<String> buildRootRemovalCommands(Context context) {
        List<String> commands = new ArrayList<>();
        // These commands are executed directly through RootCommand, not through Api.iptablesCommands.
        // Keep them fully-qualified so preference toggles and dashboard pause actually remove root state.
        commands.add(buildRepairServiceEventLogFilesCommand(context));
        commands.add(buildDirectDaemonStateCleanupCommand(context));
        appendDirectPurgeRules(context, commands, false);
        appendDirectPurgeRules(context, commands, true);
        commands.add(buildNftPurgeCommand());
        appendDirectStopCommand(context, commands);
        commands.add(buildRemoveBootPersistenceCommand());
        commands.add(buildRemoveLifecycleCleanupCommand());
        return commands;
    }

    private static List<String> buildRootEmergencyCleanupCommands(Context context) {
        List<String> commands = buildRootRemovalCommands(context);
        commands.add("echo 'DNS emergency cleanup finished'");
        return commands;
    }

    private static void requestDaemonFailOpen(Context context, String reason) {
        if (context == null) {
            return;
        }
        String response = queryControl(context, "fail_open", 5000);
        syncServiceLogsToAppLog(context);
        if (response.startsWith("ok fail_open")) {
            ApplicationErrorLog.add(context,
                    "DNS daemon fail-open control completed before " + reason + ": "
                            + compactControlResponse(response));
            return;
        }
        ApplicationErrorLog.add(context,
                "DNS daemon fail-open control unavailable before " + reason + ": "
                        + compactControlResponse(response));
    }

    private static boolean clearEnableMarkerBeforeRoot(Context context, String reason) {
        if (context == null) {
            return false;
        }
        // Root cleanup may be unavailable after the user's su grant is revoked; the app-owned
        // marker is the supervisor's no-root fail-open signal.
        List<File> dirs = new ArrayList<>();
        dirs.add(workDir(context));
        File legacyDir = legacyCredentialProtectedWorkDir(context);
        if (legacyDir != null) {
            dirs.add(legacyDir);
        }

        boolean removed = false;
        boolean failed = false;
        for (File dir : dirs) {
            File marker = new File(dir, ENABLED_MARKER);
            if (!marker.exists()) {
                continue;
            }
            if (marker.delete()) {
                removed = true;
            } else {
                failed = true;
                ApplicationErrorLog.add(context,
                        "DNS enable marker could not be cleared before " + reason
                                + ": " + marker.getAbsolutePath());
            }
        }
        if (failed) {
            ApplicationErrorLog.add(context,
                    "DNS enable marker cleanup was incomplete before " + reason
                            + "; root cleanup will try again");
            return false;
        }
        if (removed) {
            ApplicationErrorLog.add(context,
                    "DNS enable marker cleared before " + reason
                            + "; supervisor can fail open if root cleanup is unavailable");
        } else {
            ApplicationErrorLog.add(context,
                    "DNS enable marker already absent before " + reason);
        }
        return true;
    }

    private static String buildDirectDaemonStateCleanupCommand(Context context) {
        List<File> dirs = new ArrayList<>();
        dirs.add(workDir(context));
        File legacyDir = legacyCredentialProtectedWorkDir(context);
        if (legacyDir != null) {
            dirs.add(legacyDir);
        }

        StringBuilder command = new StringBuilder();
        command.append("stop_named_daemon() { ");
        command.append("signal=\"$1\"; ");
        command.append("if command -v pidof >/dev/null 2>&1; then ");
        command.append("for p in $(pidof ").append(DAEMON_NAME)
                .append(" 2>/dev/null); do kill \"$signal\" \"$p\" 2>/dev/null || true; done; ");
        command.append("fi; ");
        command.append("for proc in /proc/[0-9]*; do ");
        command.append("[ -r \"$proc/comm\" ] || continue; ");
        command.append("name=$(cat \"$proc/comm\" 2>/dev/null || true); ");
        command.append("[ \"$name\" = \"").append(DAEMON_NAME).append("\" ] || continue; ");
        command.append("pid=${proc#/proc/}; ");
        command.append("kill \"$signal\" \"$pid\" 2>/dev/null || true; ");
        command.append("done; ");
        command.append("}; ");
        command.append("for DIR in");
        for (File dir : dirs) {
            command.append(' ').append(shellQuote(dir.getAbsolutePath()));
        }
        command.append("; do ");
        command.append("[ -d \"$DIR\" ] || continue; ");
        command.append("rm -f \"$DIR/").append(ENABLED_MARKER).append("\" 2>/dev/null || true; ");
        command.append("for PIDFILE in \"$DIR/").append(SUPERVISOR_PID)
                .append("\" \"$DIR/").append(PID).append("\"; do ");
        command.append("[ -f \"$PIDFILE\" ] || continue; ");
        command.append("pid=$(cat \"$PIDFILE\" 2>/dev/null || true); ");
        command.append("case \"$pid\" in ''|*[!0-9]*) ;; *) kill -TERM \"$pid\" 2>/dev/null || true ;; esac; ");
        command.append("done; ");
        command.append("done; ");
        command.append("stop_named_daemon -TERM; ");
        command.append("sleep 1; ");
        command.append("for DIR in");
        for (File dir : dirs) {
            command.append(' ').append(shellQuote(dir.getAbsolutePath()));
        }
        command.append("; do ");
        command.append("[ -d \"$DIR\" ] || continue; ");
        command.append("for PIDFILE in \"$DIR/").append(SUPERVISOR_PID)
                .append("\" \"$DIR/").append(PID).append("\"; do ");
        command.append("[ -f \"$PIDFILE\" ] || continue; ");
        command.append("pid=$(cat \"$PIDFILE\" 2>/dev/null || true); ");
        command.append("case \"$pid\" in ''|*[!0-9]*) ;; *) kill -KILL \"$pid\" 2>/dev/null || true ;; esac; ");
        command.append("done; ");
        command.append("rm -f \"$DIR/").append(SUPERVISOR_PID)
                .append("\" \"$DIR/").append(PID)
                .append("\" \"$DIR/").append(HEARTBEAT)
                .append("\" \"$DIR/").append(SOCKET)
                .append("\" 2>/dev/null || true; ");
        command.append("done; ");
        command.append("stop_named_daemon -KILL; ");
        command.append("true");
        return command.toString();
    }

    private static void appendDirectPurgeRules(Context context, List<String> commands, boolean ipv6) {
        String iptables = shellQuote(Api.getBinaryPath(context, ipv6));
        String chain = ipv6 ? CHAIN_V6 : CHAIN_V4;
        String preChain = ipv6 ? CHAIN_V6_PRE : CHAIN_V4_PRE;

        appendDirectDaemonFilterBypassPurge(commands, iptables);
        appendDirectIptables(commands, iptables,
                "-t nat -D OUTPUT -p udp --dport 53 -j " + chain);
        appendDirectIptables(commands, iptables,
                "-t nat -D OUTPUT -p tcp --dport 53 -j " + chain);
        appendDirectIptables(commands, iptables,
                "-t nat -D PREROUTING -p udp --dport 53 -j " + preChain);
        appendDirectIptables(commands, iptables,
                "-t nat -D PREROUTING -p tcp --dport 53 -j " + preChain);
        appendDirectIptables(commands, iptables, "-t nat -F " + chain);
        appendDirectIptables(commands, iptables, "-t nat -F " + preChain);
        appendDirectIptables(commands, iptables, "-t nat -X " + chain);
        appendDirectIptables(commands, iptables, "-t nat -X " + preChain);
    }

    private static void appendDirectIptables(List<String> commands, String iptables, String args) {
        commands.add(iptables + " " + args + " >/dev/null 2>&1 || true");
    }

    private static String daemonMarkFilterBypassArgs() {
        return "-m mark --mark " + DAEMON_SOCKET_MARK + " -j ACCEPT";
    }

    private static void appendDaemonFilterBypass(Context context, List<String> commands) {
        appendDaemonFilterBypassPurge(commands);
        // The root daemon runs outside AFWall's app UID. Its upstream sockets must pass the
        // filter table, and the fallback must follow the same mark-vs-UID path as NAT recursion.
        commands.add("#LITERAL# " + buildDaemonFilterBypassInstallCommand("\"$IPTABLES\"",
                new File(workDir(context), MARK_STATUS).getAbsolutePath()));
    }

    private static void appendDaemonFilterBypassPurge(List<String> commands) {
        commands.add("#NOCHK# -D OUTPUT " + daemonMarkFilterBypassArgs());
        commands.add("#NOCHK# -D OUTPUT -j " + CHAIN_FILTER);
        commands.add("#NOCHK# -F " + CHAIN_FILTER);
        commands.add("#NOCHK# -X " + CHAIN_FILTER);
    }

    private static void appendDirectDaemonFilterBypass(Context context, List<String> commands,
                                                       String iptables) {
        appendDirectDaemonFilterBypassPurge(commands, iptables);
        commands.add(buildDaemonFilterBypassInstallCommand(iptables,
                new File(workDir(context), MARK_STATUS).getAbsolutePath()));
    }

    private static void appendDirectDaemonFilterBypassPurge(List<String> commands, String iptables) {
        appendTolerantIptables(commands, iptables, "-D OUTPUT " + daemonMarkFilterBypassArgs());
        appendTolerantIptables(commands, iptables, "-D OUTPUT -j " + CHAIN_FILTER);
        appendTolerantIptables(commands, iptables, "-F " + CHAIN_FILTER);
        appendTolerantIptables(commands, iptables, "-X " + CHAIN_FILTER);
    }

    private static String buildDaemonFilterBypassInstallCommand(String iptables,
                                                                String markStatusPath) {
        String status = shellQuote(markStatusPath);
        StringBuilder command = new StringBuilder();
        command.append("ok=1; ");
        command.append(iptables).append(" -D OUTPUT -j ").append(CHAIN_FILTER)
                .append(" >/dev/null 2>&1 || true; ");
        command.append(iptables).append(" -N ").append(CHAIN_FILTER)
                .append(" >/dev/null 2>&1 || true; ");
        command.append(iptables).append(" -F ").append(CHAIN_FILTER)
                .append(" >/dev/null 2>&1 || true; ");
        command.append("if [ -r ").append(status)
                .append(" ] && grep -q '^supported ' ").append(status).append("; then ");
        command.append(iptables).append(" -A ").append(CHAIN_FILTER).append(' ')
                .append(daemonMarkFilterBypassArgs()).append(" || ok=0; ");
        command.append("else echo 'DNS daemon mark unavailable; allowing UID 0 DNS upstream fallback through filter'; ");
        appendUid0FilterFallbackRules(command, iptables, CHAIN_FILTER);
        command.append("fi; ");
        command.append(iptables).append(" -I OUTPUT 1 -j ").append(CHAIN_FILTER)
                .append(" || ok=0; ");
        command.append("[ \"$ok\" = 1 ]");
        return command.toString();
    }

    private static void appendUid0FilterFallbackRules(StringBuilder command, String iptables,
                                                      String chain) {
        for (Integer port : dnsUpstreamPortsForFilterFallback()) {
            command.append(iptables).append(" -A ").append(chain)
                    .append(" -m owner --uid-owner 0 -p udp --dport ")
                    .append(port).append(" -j ACCEPT || ok=0; ");
            command.append(iptables).append(" -A ").append(chain)
                    .append(" -m owner --uid-owner 0 -p tcp --dport ")
                    .append(port).append(" -j ACCEPT || ok=0; ");
        }
    }

    private static void appendDaemonRecursionBypass(Context context, List<String> commands,
                                                    String iptables, String chain) {
        commands.add(buildDaemonRecursionBypassCommand(
                iptables, chain, new File(workDir(context), MARK_STATUS).getAbsolutePath()));
    }

    private static String buildDaemonRecursionBypassCommand(String iptables, String chain,
                                                            String markStatusPath) {
        String status = shellQuote(markStatusPath);
        return "( if [ -r " + status + " ] && grep -q '^supported ' " + status + "; then "
                + iptables + " -t nat -A " + chain + " -m mark --mark "
                + DAEMON_SOCKET_MARK + " -j RETURN >/dev/null 2>&1 || "
                + iptables + " -t nat -A " + chain
                + " -m owner --uid-owner 0 -j RETURN; else "
                + iptables + " -t nat -A " + chain
                + " -m owner --uid-owner 0 -j RETURN; fi )";
    }

    private static String buildApplyDaemonRecursionBypassCommand(Context context, String chain) {
        return buildDaemonRecursionBypassCommand("\"$IPTABLES\"", chain,
                new File(workDir(context), MARK_STATUS).getAbsolutePath()) + " #";
    }

    private static void appendTolerantIptables(List<String> commands, String iptables, String args) {
        commands.add(iptables + " " + args + " >/dev/null 2>&1 || true");
    }

    private static void appendDirectStopCommand(Context context, List<String> commands) {
        if (context == null) {
            return;
        }
        appendSupervisorStopCommand(commands, new File(workDir(context), SUPERVISOR));
        appendLegacySupervisorStopCommand(context, commands, false);
    }

    private static void appendLegacySupervisorStopCommand(Context context, List<String> commands,
                                                          boolean literal) {
        File legacyDir = legacyCredentialProtectedWorkDir(context);
        if (legacyDir != null) {
            appendSupervisorStopCommand(commands, new File(legacyDir, SUPERVISOR), literal);
        }
    }

    private static void appendSupervisorStopCommand(List<String> commands, File supervisor) {
        appendSupervisorStopCommand(commands, supervisor, false);
    }

    private static void appendSupervisorStopCommand(List<String> commands, File supervisor,
                                                    boolean literal) {
        if (supervisor.exists()) {
            commands.add((literal ? "#LITERAL# " : "")
                    + shellQuote(supervisor.getAbsolutePath()) + " stop || true");
        }
    }

    private static void appendRootRedirectRepairCommands(Context context, List<String> commands, boolean ipv6) {
        String iptables = shellQuote(Api.getBinaryPath(context, ipv6));
        int port = G.dnsHijackPort(DEFAULT_PORT);
        String chain = ipv6 ? CHAIN_V6 : CHAIN_V4;
        String preChain = ipv6 ? CHAIN_V6_PRE : CHAIN_V4_PRE;

        appendDirectDaemonFilterBypass(context, commands, iptables);
        appendTolerantIptables(commands, iptables, "-t nat -D OUTPUT -p udp --dport 53 -j " + chain);
        appendTolerantIptables(commands, iptables, "-t nat -D OUTPUT -p tcp --dport 53 -j " + chain);
        appendTolerantIptables(commands, iptables, "-t nat -D PREROUTING -p udp --dport 53 -j " + preChain);
        appendTolerantIptables(commands, iptables, "-t nat -D PREROUTING -p tcp --dport 53 -j " + preChain);
        appendTolerantIptables(commands, iptables, "-t nat -N " + chain);
        appendTolerantIptables(commands, iptables, "-t nat -N " + preChain);
        appendTolerantIptables(commands, iptables, "-t nat -F " + chain);
        appendTolerantIptables(commands, iptables, "-t nat -F " + preChain);
        appendTolerantIptables(commands, iptables, "-t nat -A " + chain + " -o lo -j RETURN");
        appendDaemonRecursionBypass(context, commands, iptables, chain);
        if (!appendOutputPolicyRules(commands, iptables + " -t nat -A " + chain, port, true)) {
            appendTolerantIptables(commands, iptables,
                    "-t nat -A " + chain + " -p udp --dport 53 -j REDIRECT --to-ports " + port);
            appendTolerantIptables(commands, iptables,
                    "-t nat -A " + chain + " -p tcp --dport 53 -j REDIRECT --to-ports " + port);
        }
        appendTolerantIptables(commands, iptables, "-t nat -A " + preChain + " -i lo -j RETURN");
        if (!appendPreroutingPolicyRules(commands, iptables + " -t nat -A " + preChain,
                port, true)) {
            appendTolerantIptables(commands, iptables,
                    "-t nat -A " + preChain + " -p udp --dport 53 -j REDIRECT --to-ports " + port);
            appendTolerantIptables(commands, iptables,
                    "-t nat -A " + preChain + " -p tcp --dport 53 -j REDIRECT --to-ports " + port);
        }
        appendTolerantIptables(commands, iptables, "-t nat -I OUTPUT 1 -p udp --dport 53 -j " + chain);
        appendTolerantIptables(commands, iptables, "-t nat -I OUTPUT 1 -p tcp --dport 53 -j " + chain);
        appendTolerantIptables(commands, iptables,
                "-t nat -I PREROUTING 1 -p udp --dport 53 -j " + preChain);
        appendTolerantIptables(commands, iptables,
                "-t nat -I PREROUTING 1 -p tcp --dport 53 -j " + preChain);
        commands.add(buildNftFallbackRestoreCommand(context, ipv6));
        commands.add(buildRedirectInstallVerificationCommand(context, ipv6));
    }

    private static void appendRedirectRules(Context context, List<String> commands, boolean ipv6) {
        int port = G.dnsHijackPort(DEFAULT_PORT);
        String chain = ipv6 ? CHAIN_V6 : CHAIN_V4;
        String preChain = ipv6 ? CHAIN_V6_PRE : CHAIN_V4_PRE;

        commands.add("#NOCHK# -t nat -N " + chain);
        commands.add("#NOCHK# -t nat -N " + preChain);
        commands.add("#NOCHK# -t nat -F " + chain);
        commands.add("#NOCHK# -t nat -F " + preChain);

        appendDaemonFilterBypass(context, commands);
        commands.add("#NOCHK# -t nat -A " + chain + " -o lo -j RETURN");
        commands.add("#LITERAL# " + buildApplyDaemonRecursionBypassCommand(context, chain));
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

        appendDaemonFilterBypassPurge(commands);
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
            ensureLocalServiceEventLogFiles(dir);

            File daemon = new File(dir, DAEMON_NAME);
            copyDaemonAsset(context, daemon);
            if (!daemon.setExecutable(true, false)) {
                Log.w(TAG, "Unable to mark daemon executable from app context; root start will chmod it");
            }

            String token = controlToken(context);
            if (token.isEmpty()) {
                throw new IOException("Unable to create DNS control token");
            }
            File config = new File(dir, CONF);
            writeText(config, buildConfig(context, token));
            setOwnerOnly(config);
            File supervisor = new File(dir, SUPERVISOR);
            writeText(supervisor, buildSupervisorScript(context, dir, daemon));
            if (!supervisor.setExecutable(true, false)) {
                Log.w(TAG, "Unable to mark supervisor executable from app context; root start will chmod it");
            }
            File bootScript = new File(dir, BOOT_SCRIPT);
            writeText(bootScript, buildBootScript(context, dir));
            if (!bootScript.setExecutable(true, false)) {
                Log.w(TAG, "Unable to mark DNS boot script executable from app context; root install will chmod it");
            }
            File cleanupScript = new File(dir, CLEANUP_SCRIPT);
            writeText(cleanupScript, buildLifecycleCleanupScript(context, dir));
            if (!cleanupScript.setExecutable(true, false)) {
                Log.w(TAG, "Unable to mark DNS cleanup script executable from app context; root install will chmod it");
            }
            writeText(new File(dir, MAGISK_MODULE_PROP), buildMagiskModuleProp());
            File moduleService = new File(dir, MAGISK_SERVICE_SCRIPT);
            writeText(moduleService, buildMagiskServiceScript(context, dir));
            if (!moduleService.setExecutable(true, false)) {
                Log.w(TAG, "Unable to mark DNS Magisk service script executable from app context; root install will chmod it");
            }
            File moduleUninstall = new File(dir, MAGISK_UNINSTALL_SCRIPT);
            writeText(moduleUninstall, buildMagiskUninstallScript(dir));
            if (!moduleUninstall.setExecutable(true, false)) {
                Log.w(TAG, "Unable to mark DNS Magisk uninstall script executable from app context; root install will chmod it");
            }
            return true;
        } catch (IOException e) {
            Log.e(TAG, "Unable to prepare DNS daemon", e);
            ApplicationErrorLog.add(context, "Unable to prepare DNS hijacker daemon: " + e.getMessage());
            return false;
        }
    }

    private static void ensureLocalServiceEventLogFiles(File dir) throws IOException {
        if (dir == null) {
            return;
        }
        for (String logName : SERVICE_EVENT_LOGS) {
            File logFile = new File(dir, logName);
            if (!logFile.exists() && !logFile.createNewFile()) {
                throw new IOException("Unable to create " + logFile.getAbsolutePath());
            }
            // Root appends lifecycle events, but AFWall must be able to read them back later.
            logFile.setReadable(true, false);
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

    private static String buildMagiskModuleProp() {
        return "id=" + MAGISK_MODULE_ID + "\n"
                + "name=AFWall DNS Service\n"
                + "version=" + MAGISK_MODULE_VERSION + "\n"
                + "versionCode=" + MAGISK_MODULE_VERSION_CODE + "\n"
                + "author=AFWall+\n"
                + "description=Runs AFWall DNS protection through a Magisk service wrapper with fail-open cleanup.\n";
    }

    private static String buildMagiskServiceScript(Context context, File dir) {
        String boot = new File(dir, BOOT_SCRIPT).getAbsolutePath();
        String cleanup = new File(dir, CLEANUP_SCRIPT).getAbsolutePath();
        String marker = new File(dir, ENABLED_MARKER).getAbsolutePath();
        String packageName = context.getPackageName();
        return "#!/system/bin/sh\n"
                + "AFWALL_DNS_MODULE_SCRIPT_VERSION=" + MAGISK_SCRIPT_VERSION + "\n"
                + "MODDIR=${0%/*}\n"
                + "PACKAGE=" + shellQuote(packageName) + "\n"
                + "BOOT=" + shellQuote(boot) + "\n"
                + "CLEANUP=" + shellQuote(cleanup) + "\n"
                + "MARKER=" + shellQuote(marker) + "\n"
                + "LOG=/data/local/tmp/" + MAGISK_MODULE_LOG + "\n"
                + "log_msg() { echo \"$(date +%s) $*\" >> \"$LOG\" 2>/dev/null || true; chmod 644 \"$LOG\" 2>/dev/null || true; }\n"
                + "app_installed() { pm path \"$PACKAGE\" >/dev/null 2>&1; }\n"
                + buildMagiskEmbeddedCleanupScript()
                + "log_msg 'AFWall DNS Magisk service starting'\n"
                + "if app_installed && [ -x \"$BOOT\" ] && [ -f \"$MARKER\" ]; then\n"
                + "  \"$BOOT\" >> \"$LOG\" 2>&1\n"
                + "  exit $?\n"
                + "fi\n"
                + "log_msg 'AFWall package, enable marker, or boot script missing; cleaning DNS state and scheduling module removal'\n"
                + "rm -f \"$MARKER\" 2>/dev/null || true\n"
                + "if [ -x \"$CLEANUP\" ]; then \"$CLEANUP\" >> \"$LOG\" 2>&1; else cleanup_service_state; fi\n"
                + "touch \"$MODDIR/disable\" \"$MODDIR/remove\" 2>/dev/null || true\n"
                + "exit 0\n";
    }

    private static String buildMagiskUninstallScript(File dir) {
        String cleanup = new File(dir, CLEANUP_SCRIPT).getAbsolutePath();
        String marker = new File(dir, ENABLED_MARKER).getAbsolutePath();
        return "#!/system/bin/sh\n"
                + "AFWALL_DNS_MODULE_SCRIPT_VERSION=" + MAGISK_SCRIPT_VERSION + "\n"
                + "CLEANUP=" + shellQuote(cleanup) + "\n"
                + "MARKER=" + shellQuote(marker) + "\n"
                + "LOG=/data/local/tmp/" + MAGISK_MODULE_LOG + "\n"
                + "log_msg() { echo \"$(date +%s) $*\" >> \"$LOG\" 2>/dev/null || true; chmod 644 \"$LOG\" 2>/dev/null || true; }\n"
                + buildMagiskEmbeddedCleanupScript()
                + "log_msg 'AFWall DNS Magisk module uninstall cleanup starting'\n"
                + "if [ -x \"$CLEANUP\" ]; then \"$CLEANUP\" >> \"$LOG\" 2>&1; else cleanup_service_state; fi\n"
                + "log_msg 'AFWall DNS Magisk module uninstall cleanup complete'\n";
    }

    private static String buildMagiskEmbeddedCleanupScript() {
        return "ipt() { if command -v iptables >/dev/null 2>&1; then iptables \"$@\"; else return 0; fi; }\n"
                + "ip6t() { if command -v ip6tables >/dev/null 2>&1; then ip6tables \"$@\"; else return 0; fi; }\n"
                + "kill_daemon_processes() {\n"
                + "  signal=\"$1\"\n"
                + "  if command -v pidof >/dev/null 2>&1; then\n"
                + "    for p in $(pidof " + DAEMON_NAME + " 2>/dev/null); do kill \"$signal\" \"$p\" 2>/dev/null || true; done\n"
                + "  fi\n"
                + "  for proc in /proc/[0-9]*; do\n"
                + "    [ -r \"$proc/comm\" ] || continue\n"
                + "    name=$(cat \"$proc/comm\" 2>/dev/null || true)\n"
                + "    [ \"$name\" = \"" + DAEMON_NAME + "\" ] || continue\n"
                + "    pid=${proc#/proc/}\n"
                + "    kill \"$signal\" \"$pid\" 2>/dev/null || true\n"
                + "  done\n"
                + "}\n"
                + "stop_daemon() {\n"
                + "  log_msg 'Magisk wrapper stopping stale AFWall DNS daemon processes'\n"
                + "  kill_daemon_processes -TERM\n"
                + "  sleep 1\n"
                + "  kill_daemon_processes -KILL\n"
                + "}\n"
                + "cleanup_redirects() {\n"
                + "  log_msg 'Magisk wrapper removing stale AFWall DNS redirect rules'\n"
                + "  ipt -D OUTPUT -m mark --mark " + DAEMON_SOCKET_MARK + " -j ACCEPT >/dev/null 2>&1 || true\n"
                + "  ip6t -D OUTPUT -m mark --mark " + DAEMON_SOCKET_MARK + " -j ACCEPT >/dev/null 2>&1 || true\n"
                + "  ipt -D OUTPUT -j " + CHAIN_FILTER + " >/dev/null 2>&1 || true\n"
                + "  ipt -F " + CHAIN_FILTER + " >/dev/null 2>&1 || true\n"
                + "  ipt -X " + CHAIN_FILTER + " >/dev/null 2>&1 || true\n"
                + "  ip6t -D OUTPUT -j " + CHAIN_FILTER + " >/dev/null 2>&1 || true\n"
                + "  ip6t -F " + CHAIN_FILTER + " >/dev/null 2>&1 || true\n"
                + "  ip6t -X " + CHAIN_FILTER + " >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -D OUTPUT -p udp --dport 53 -j " + CHAIN_V4 + " >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -D OUTPUT -p tcp --dport 53 -j " + CHAIN_V4 + " >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -D PREROUTING -p udp --dport 53 -j " + CHAIN_V4_PRE + " >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -D PREROUTING -p tcp --dport 53 -j " + CHAIN_V4_PRE + " >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -F " + CHAIN_V4 + " >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -F " + CHAIN_V4_PRE + " >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -X " + CHAIN_V4 + " >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -X " + CHAIN_V4_PRE + " >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -D OUTPUT -p udp --dport 53 -j " + CHAIN_V6 + " >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -D OUTPUT -p tcp --dport 53 -j " + CHAIN_V6 + " >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -D PREROUTING -p udp --dport 53 -j " + CHAIN_V6_PRE + " >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -D PREROUTING -p tcp --dport 53 -j " + CHAIN_V6_PRE + " >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -F " + CHAIN_V6 + " >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -F " + CHAIN_V6_PRE + " >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -X " + CHAIN_V6 + " >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -X " + CHAIN_V6_PRE + " >/dev/null 2>&1 || true\n"
                + "  if command -v nft >/dev/null 2>&1; then nft delete table ip " + NFT_TABLE_V4 + " >/dev/null 2>&1 || true; nft delete table ip6 " + NFT_TABLE_V6 + " >/dev/null 2>&1 || true; fi\n"
                + "}\n"
                + "remove_root_copies() {\n"
                + "  log_msg 'Magisk wrapper removing legacy AFWall DNS startup hooks'\n"
                + "  for FILE in /data/adb/service.d/" + BOOT_SCRIPT
                + " /su/su.d/" + BOOT_SCRIPT
                + " /system/su.d/" + BOOT_SCRIPT
                + " /system/etc/init.d/" + BOOT_SCRIPT
                + " /data/adb/service.d/" + CLEANUP_SCRIPT
                + " /su/su.d/" + CLEANUP_SCRIPT
                + " /system/su.d/" + CLEANUP_SCRIPT
                + " /system/etc/init.d/" + CLEANUP_SCRIPT
                + "; do [ -e \"$FILE\" ] && rm -f \"$FILE\" 2>/dev/null || true; done\n"
                + "}\n"
                + "cleanup_service_state() {\n"
                + "  if [ -n \"${MARKER:-}\" ]; then rm -f \"$MARKER\" 2>/dev/null || true; fi\n"
                + "  stop_daemon\n"
                + "  cleanup_redirects\n"
                + "  remove_root_copies\n"
                + "}\n";
    }

    private static String buildConfig(Context context, String controlToken) {
        File dir = workDir(context);
        StringBuilder config = new StringBuilder();
        G.pruneExpiredDnsHijackTemporaryRules();
        config.append("port=").append(G.dnsHijackPort(DEFAULT_PORT)).append('\n');
        config.append("control_socket=").append(new File(dir, SOCKET).getAbsolutePath()).append('\n');
        config.append("control_socket_uid=").append(context.getApplicationInfo().uid).append('\n');
        config.append("control_token=").append(controlToken).append('\n');
        config.append("pid_file=").append(new File(dir, PID).getAbsolutePath()).append('\n');
        config.append("heartbeat_file=").append(new File(dir, HEARTBEAT).getAbsolutePath()).append('\n');
        config.append("mark_status_file=").append(new File(dir, MARK_STATUS).getAbsolutePath()).append('\n');
        config.append("iptables_path=").append(Api.getBinaryPath(context, false)).append('\n');
        config.append("ip6tables_path=").append(Api.getBinaryPath(context, true)).append('\n');
        config.append("event_log_file=")
                .append(new File(dir, DAEMON_EVENT_LOG).getAbsolutePath()).append('\n');
        config.append("log_file=").append(new File(dir, QUERY_LOG).getAbsolutePath()).append('\n');
        config.append("cache_file=").append(new File(dir, "cache.snapshot").getAbsolutePath()).append('\n');
        config.append("fail_open=").append(G.dnsHijackFailOpen() ? "1" : "0").append('\n');
        config.append("strict_mode=").append(G.dnsHijackStrictMode() ? "1" : "0").append('\n');
        config.append("timeout_ms=").append(G.dnsHijackTimeoutMs()).append('\n');
        config.append("cache_size=").append(G.dnsHijackCacheSize()).append('\n');
        config.append("stale_cache_seconds=").append(G.dnsHijackStaleCacheSeconds()).append('\n');
        config.append("persist_cache=").append(G.dnsHijackPersistCache() ? "1" : "0").append('\n');
        config.append("query_logging=").append(G.dnsHijackQueryLogging() ? "1" : "0").append('\n');
        config.append("persist_query_logs=").append(G.dnsHijackPersistQueryLogs() ? "1" : "0").append('\n');
        config.append("dnssec_request=").append(G.dnsHijackDnssecRequest() ? "1" : "0").append('\n');
        config.append("dnssec_auth_required=")
                .append(G.dnsHijackDnssecAuthRequired() ? "1" : "0").append('\n');
        appendSafeSearchConfigEntries(context, config);

        appendResolvedUpstreamConfigEntries(context, config, "upstream", G.dnsHijackUpstreams());
        appendResolvedSplitUpstreamConfigEntries(context, config, G.dnsHijackSplitUpstreams());
        appendConfigEntries(config, "allow_exact", G.dnsHijackAllowExact());
        appendConfigEntries(config, "allow_suffix", G.dnsHijackAllowSuffix());
        appendConfigEntries(config, "block_exact", G.dnsHijackBlockExact());
        appendConfigEntries(config, "block_suffix", G.dnsHijackBlockSuffix());
        appendConfigEntries(config, "app_allow_exact", G.dnsHijackAppAllowExact());
        appendConfigEntries(config, "app_block_exact", G.dnsHijackAppBlockExact());
        appendConfigEntries(config, "app_allow_suffix", G.dnsHijackAppAllowSuffix());
        appendConfigEntries(config, "app_block_suffix", G.dnsHijackAppBlockSuffix());
        appendConfigEntries(config, "network_allow", G.dnsHijackNetworkAllow());
        appendConfigEntries(config, "network_block", G.dnsHijackNetworkBlock());
        appendConfigEntries(config, "allow_regex", G.dnsHijackAllowRegex());
        appendConfigEntries(config, "block_regex", G.dnsHijackBlockRegex());
        appendConfigEntries(config, "temp_allow", G.dnsHijackTempAllow());
        appendConfigEntries(config, "temp_block", G.dnsHijackTempBlock());
        appendConfigFile(config, "block_exact_file", DnsBlocklistManager.exactBlockFile(context));
        appendConfigFile(config, "block_suffix_file", DnsBlocklistManager.suffixBlockFile(context));

        return config.toString();
    }

    private static void appendSafeSearchConfigEntries(Context context, StringBuilder config) {
        boolean enabled = G.dnsHijackSafeSearch();
        config.append("safe_search=").append(enabled ? "1" : "0").append('\n');
        if (!enabled) {
            return;
        }
        appendSafeSearchProvider(context, config, "google", "forcesafesearch.google.com",
                "216.239.38.120", "2001:4860:4802:32::78");
        appendSafeSearchProvider(context, config, "youtube", "restrict.youtube.com",
                "216.239.38.120", "2001:4860:4802:32::78");
        appendSafeSearchProvider(context, config, "bing", "strict.bing.com",
                "204.79.197.220");
        appendSafeSearchProvider(context, config, "duckduckgo", "safe.duckduckgo.com");
    }

    private static void appendSafeSearchProvider(Context context, StringBuilder config,
                                                 String provider, String targetHost,
                                                 String... fallbackAddresses) {
        List<String> addresses = resolveWithBootstrap(context, targetHost);
        if (addresses.isEmpty()) {
            for (String fallback : fallbackAddresses) {
                if (fallback != null && !fallback.trim().isEmpty() && !addresses.contains(fallback)) {
                    addresses.add(fallback);
                }
            }
        }
        if (addresses.isEmpty()) {
            ApplicationErrorLog.add(context, "DNS SafeSearch target could not be resolved: " + targetHost);
            return;
        }
        for (String address : addresses) {
            config.append("safe_search_address=").append(provider).append('|')
                    .append(address).append('\n');
        }
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

    private static void appendResolvedUpstreamConfigEntries(Context context, StringBuilder config,
                                                            String key, String raw) {
        if (raw == null) {
            return;
        }
        String[] lines = raw.split("[\\r\\n,]+");
        for (String line : lines) {
            String value = line == null ? "" : line.trim();
            if (value.isEmpty() || value.startsWith("#")) {
                continue;
            }
            for (String resolved : resolveUpstreamValue(context, value)) {
                config.append(key).append('=').append(resolved).append('\n');
            }
        }
    }

    private static void appendResolvedSplitUpstreamConfigEntries(Context context, StringBuilder config,
                                                                 String raw) {
        if (raw == null) {
            return;
        }
        String[] lines = raw.split("\\r?\\n");
        for (String line : lines) {
            String value = line == null ? "" : line.trim();
            int separator = findSplitSeparator(value);
            if (value.isEmpty() || value.startsWith("#") || separator <= 0) {
                continue;
            }
            String suffix = value.substring(0, separator).trim().toLowerCase(Locale.US);
            String upstream = value.substring(separator + 1).trim();
            if (upstream.isEmpty()) {
                continue;
            }
            for (String resolved : resolveUpstreamValue(context, upstream)) {
                config.append("split_upstream=").append(suffix).append('=')
                        .append(resolved).append('\n');
            }
        }
    }

    private static int findSplitSeparator(String value) {
        int separator = value.indexOf('|');
        if (separator < 0) {
            separator = value.indexOf('=');
        }
        if (separator < 0) {
            for (int i = 0; i < value.length(); i++) {
                if (Character.isWhitespace(value.charAt(i))) {
                    return i;
                }
            }
        }
        return separator;
    }

    private static List<String> resolveUpstreamValue(Context context, String value) {
        List<String> resolvedValues = new ArrayList<>();
        UpstreamTarget target = UpstreamTarget.parse(value);
        if (target == null) {
            ApplicationErrorLog.add(context, "DNS upstream entry ignored because it is invalid or unsupported: "
                    + safeLogValue(value));
            return resolvedValues;
        }
        if (target.hasLiteralHost()) {
            resolvedValues.add(target.toConfigValue());
            return resolvedValues;
        }

        List<String> addresses = resolveWithBootstrap(context, target.host);
        if (addresses.isEmpty()) {
            ApplicationErrorLog.add(context, "DNS bootstrap resolution failed for upstream " + target.host);
            resolvedValues.add(target.toConfigValue());
            return resolvedValues;
        }
        for (String address : addresses) {
            resolvedValues.add(new UpstreamTarget(address, target.port, target.protocol).toConfigValue());
        }
        return resolvedValues;
    }

    private static List<String> resolveWithBootstrap(Context context, String host) {
        List<String> addresses = new ArrayList<>();
        List<UpstreamTarget> bootstrapTargets = parseUpstreamTargets(G.dnsHijackBootstrapUpstreams());
        if (bootstrapTargets.isEmpty()) {
            bootstrapTargets = parseUpstreamTargets("1.1.1.1:53\n8.8.8.8:53");
        }
        for (UpstreamTarget bootstrap : bootstrapTargets) {
            if (!bootstrap.hasLiteralHost()) {
                continue;
            }
            addResolvedAddresses(addresses, queryBootstrap(bootstrap, host, 1), 1);
            addResolvedAddresses(addresses, queryBootstrap(bootstrap, host, 28), 28);
            if (!addresses.isEmpty()) {
                ApplicationErrorLog.add(context, "DNS bootstrap resolved " + host
                        + " using " + bootstrap.toConfigValue() + " addresses=" + addresses.size());
                break;
            }
        }
        return addresses;
    }

    private static byte[] queryBootstrap(UpstreamTarget bootstrap, String host, int qtype) {
        byte[] query = buildDnsLookupQuery(host, qtype);
        if (query == null) {
            return null;
        }
        if ("tcp".equals(bootstrap.protocol)) {
            return queryBootstrapTcp(bootstrap, query);
        }
        return queryBootstrapUdp(bootstrap, query);
    }

    private static byte[] queryBootstrapUdp(UpstreamTarget bootstrap, byte[] query) {
        int timeoutMs = Math.min(Math.max(G.dnsHijackTimeoutMs(), 250), 1500);
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(timeoutMs);
            InetAddress address = InetAddress.getByName(bootstrap.host);
            DatagramPacket request = new DatagramPacket(query, query.length, address, bootstrap.port);
            socket.send(request);
            byte[] response = new byte[1500];
            DatagramPacket reply = new DatagramPacket(response, response.length);
            socket.receive(reply);
            byte[] copy = new byte[reply.getLength()];
            System.arraycopy(response, 0, copy, 0, reply.getLength());
            return copy;
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    private static byte[] queryBootstrapTcp(UpstreamTarget bootstrap, byte[] query) {
        int timeoutMs = Math.min(Math.max(G.dnsHijackTimeoutMs(), 250), 1500);
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(InetAddress.getByName(bootstrap.host), bootstrap.port), timeoutMs);
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
                return null;
            }
            int expected = (high << 8) | low;
            if (expected <= 0 || expected > 4096) {
                return null;
            }
            byte[] response = new byte[expected];
            int read = readFully(input, response, expected);
            return read == expected ? response : null;
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    private static byte[] buildDnsLookupQuery(String host, int qtype) {
        String clean = host == null ? "" : host.trim().toLowerCase(Locale.US);
        if (clean.isEmpty()) {
            return null;
        }
        ByteArrayOutputStream query = new ByteArrayOutputStream();
        int id = (int) (System.currentTimeMillis() & 0xffff);
        query.write((id >> 8) & 0xff);
        query.write(id & 0xff);
        query.write(0x01);
        query.write(0x00);
        query.write(0x00);
        query.write(0x01);
        query.write(0x00);
        query.write(0x00);
        query.write(0x00);
        query.write(0x00);
        query.write(0x00);
        query.write(0x00);
        String[] labels = clean.split("\\.");
        for (String label : labels) {
            if (label.isEmpty() || label.length() > 63) {
                return null;
            }
            byte[] labelBytes = label.getBytes(StandardCharsets.US_ASCII);
            query.write(labelBytes.length);
            query.write(labelBytes, 0, labelBytes.length);
        }
        query.write(0x00);
        query.write((qtype >> 8) & 0xff);
        query.write(qtype & 0xff);
        query.write(0x00);
        query.write(0x01);
        return query.toByteArray();
    }

    private static String safeLogValue(String raw) {
        String clean = raw == null ? "" : raw.trim().replace('\n', ' ').replace('\r', ' ');
        clean = clean.replaceAll("\\s+", " ");
        if (clean.length() > 120) {
            clean = clean.substring(0, 120);
        }
        return clean.isEmpty() ? "empty" : clean;
    }

    private static void addResolvedAddresses(List<String> addresses, byte[] response, int qtype) {
        if (response == null || response.length < 12) {
            return;
        }
        int qdCount = readU16(response, 4);
        int anCount = readU16(response, 6);
        int offset = 12;
        for (int i = 0; i < qdCount; i++) {
            offset = skipDnsName(response, offset);
            if (offset < 0 || offset + 4 > response.length) {
                return;
            }
            offset += 4;
        }
        for (int i = 0; i < anCount; i++) {
            offset = skipDnsName(response, offset);
            if (offset < 0 || offset + 10 > response.length) {
                return;
            }
            int type = readU16(response, offset);
            int clazz = readU16(response, offset + 2);
            int rdLength = readU16(response, offset + 8);
            offset += 10;
            if (offset + rdLength > response.length) {
                return;
            }
            if (clazz == 1 && type == qtype && (rdLength == 4 || rdLength == 16)) {
                byte[] raw = new byte[rdLength];
                System.arraycopy(response, offset, raw, 0, rdLength);
                try {
                    String address = InetAddress.getByAddress(raw).getHostAddress();
                    if (!addresses.contains(address)) {
                        addresses.add(address);
                    }
                } catch (IOException ignored) {
                }
            }
            offset += rdLength;
        }
    }

    private static int skipDnsName(byte[] packet, int offset) {
        int jumps = 0;
        while (offset >= 0 && offset < packet.length && jumps < 128) {
            int length = packet[offset] & 0xff;
            if (length == 0) {
                return offset + 1;
            }
            if ((length & 0xc0) == 0xc0) {
                return offset + 2;
            }
            offset += length + 1;
            jumps++;
        }
        return -1;
    }

    private static int readU16(byte[] packet, int offset) {
        if (offset < 0 || offset + 1 >= packet.length) {
            return 0;
        }
        return ((packet[offset] & 0xff) << 8) | (packet[offset + 1] & 0xff);
    }

    private static String buildBootNftFallbackRestore(boolean ipv6, int port) {
        String tool = ipv6 ? "ip6t" : "ipt";
        String chainVariable = ipv6 ? "$CHAIN6" : "$CHAIN4";
        String preChainVariable = ipv6 ? "$PRE6" : "$PRE4";
        String family = ipv6 ? "ip6" : "ip";
        String table = ipv6 ? NFT_TABLE_V6 : NFT_TABLE_V4;
        return "  if command -v nft >/dev/null 2>&1; then\n"
                + "    if ! ( " + buildBootIptablesRedirectHealthyCondition(tool,
                chainVariable, preChainVariable, port) + " ); then\n"
                + "      log_msg 'DNS nftables fallback restore starting for " + family + "'\n"
                + "      ( " + buildNftRuntimeRestoreCommands(family, table,
                String.valueOf(port), "\"$MARK_STATUS\"") + " ) >> \"$LOG\" 2>&1\n"
                + "    else\n"
                + "      nft delete table " + family + " " + table + " >/dev/null 2>&1 || true\n"
                + "    fi\n"
                + "  fi\n";
    }

    private static String buildBootIptablesRedirectHealthyCondition(String tool, String chainVariable,
                                                                    String preChainVariable,
                                                                    int port) {
        List<String> checks = new ArrayList<>();
        checks.add(buildBootIptablesRuleCheck(tool, "OUTPUT", "udp", chainVariable));
        checks.add(buildBootIptablesRuleCheck(tool, "OUTPUT", "tcp", chainVariable));
        if (preroutingRedirectExpected()) {
            checks.add(buildBootIptablesRuleCheck(tool, "PREROUTING", "udp", preChainVariable));
            checks.add(buildBootIptablesRuleCheck(tool, "PREROUTING", "tcp", preChainVariable));
        }
        checks.add(buildBootIptablesRecursionGuardCheck(tool, chainVariable));
        checks.add(buildBootIptablesDaemonPathFilterCheck(tool, chainVariable));
        checks.add(buildBootIptablesRedirectTargetCheck(tool, chainVariable, "udp", port));
        checks.add(buildBootIptablesRedirectTargetCheck(tool, chainVariable, "tcp", port));
        if (preroutingRedirectExpected()) {
            checks.add(buildBootIptablesRedirectTargetCheck(tool, preChainVariable, "udp", port));
            checks.add(buildBootIptablesRedirectTargetCheck(tool, preChainVariable, "tcp", port));
        }
        return joinShellChecks(checks);
    }

    private static String buildBootIptablesRuleCheck(String tool, String parentChain,
                                                     String protocol, String targetChainVariable) {
        return tool + " -t nat -S " + parentChain
                + " 2>/dev/null | grep -q -- \"-p " + protocol
                + " .*--dport 53.*-j " + targetChainVariable + "\"";
    }

    private static String buildBootIptablesRecursionGuardCheck(String tool,
                                                               String chainVariable) {
        return "( " + buildBootIptablesDaemonMarkReturnCheck(tool, chainVariable)
                + " || " + buildBootIptablesUid0ReturnCheck(tool, chainVariable) + " )";
    }

    private static String buildBootIptablesDaemonPathFilterCheck(String tool,
                                                                 String chainVariable) {
        return "( ( " + buildBootIptablesDaemonMarkReturnCheck(tool, chainVariable)
                + " && " + buildBootIptablesDaemonMarkFilterAcceptCheck(tool)
                + " ) || " + buildBootIptablesUid0ReturnCheck(tool, chainVariable) + " )";
    }

    private static String buildBootIptablesDaemonMarkReturnCheck(String tool,
                                                                 String chainVariable) {
        return tool + " -t nat -S \"" + chainVariable + "\""
                + " 2>/dev/null | grep -q -- \"-m mark .*--mark "
                + DAEMON_SOCKET_MARK + ".*-j RETURN\"";
    }

    private static String buildBootIptablesDaemonMarkFilterAcceptCheck(String tool) {
        return tool + " -S OUTPUT"
                + " 2>/dev/null | grep -q -- \"-m mark .*--mark "
                + DAEMON_SOCKET_MARK + ".*-j ACCEPT\"";
    }

    private static String buildBootIptablesUid0ReturnCheck(String tool, String chainVariable) {
        return tool + " -t nat -S \"" + chainVariable + "\""
                + " 2>/dev/null | grep -q -- \"-m owner .*--uid-owner 0.*-j RETURN\"";
    }

    private static String buildBootIptablesRedirectTargetCheck(String tool, String chainVariable,
                                                               String protocol, int port) {
        return tool + " -t nat -S \"" + chainVariable + "\""
                + " 2>/dev/null | grep -q -- \"-p " + protocol
                + " .*--dport 53.*-j REDIRECT.*--to-ports " + port + "\"";
    }

    private static String buildLifecycleCleanupScript(Context context, File dir) {
        String supervisor = new File(dir, SUPERVISOR).getAbsolutePath();
        String marker = new File(dir, ENABLED_MARKER).getAbsolutePath();
        String pid = new File(dir, PID).getAbsolutePath();
        String supervisorPid = new File(dir, SUPERVISOR_PID).getAbsolutePath();
        String appLog = new File(dir, CLEANUP_LOG).getAbsolutePath();
        String iptables = Api.getBinaryPath(context, false);
        String ip6tables = Api.getBinaryPath(context, true);
        String packageName = context.getPackageName();

        return "#!/system/bin/sh\n"
                + "AFWALL_DNS_MODULE_SCRIPT_VERSION=" + MAGISK_SCRIPT_VERSION + "\n"
                + "PATH=/system/bin:/system/xbin:/vendor/bin:/sbin:/su/bin:/data/adb/magisk:$PATH\n"
                + "PACKAGE=" + shellQuote(packageName) + "\n"
                + "DIR=" + shellQuote(dir.getAbsolutePath()) + "\n"
                + "SUPERVISOR=" + shellQuote(supervisor) + "\n"
                + "MARKER=" + shellQuote(marker) + "\n"
                + "PID_FILE=" + shellQuote(pid) + "\n"
                + "SUP_PID=" + shellQuote(supervisorPid) + "\n"
                + "APP_LOG=" + shellQuote(appLog) + "\n"
                + "FALLBACK_LOG=/data/local/tmp/" + CLEANUP_LOG + "\n"
                + "IPTABLES=" + shellQuote(iptables) + "\n"
                + "IP6TABLES=" + shellQuote(ip6tables) + "\n"
                + "CHAIN4=" + CHAIN_V4 + "\n"
                + "PRE4=" + CHAIN_V4_PRE + "\n"
                + "CHAIN6=" + CHAIN_V6 + "\n"
                + "PRE6=" + CHAIN_V6_PRE + "\n"
                + "FILTER=" + CHAIN_FILTER + "\n"
                + "if [ -d \"$DIR\" ]; then LOG=\"$APP_LOG\"; else LOG=\"$FALLBACK_LOG\"; fi\n"
                + "log_msg() {\n"
                + "  echo \"$(date +%s) $*\" >> \"$LOG\" 2>/dev/null || true\n"
                + "  chmod 644 \"$LOG\" 2>/dev/null || true\n"
                + "}\n"
                + "app_installed() {\n"
                + "  pm path \"$PACKAGE\" >/dev/null 2>&1\n"
                + "}\n"
                + "ipt() {\n"
                + "  if [ -x \"$IPTABLES\" ]; then \"$IPTABLES\" \"$@\"; elif command -v iptables >/dev/null 2>&1; then iptables \"$@\"; else return 0; fi\n"
                + "}\n"
                + "ip6t() {\n"
                + "  if [ -x \"$IP6TABLES\" ]; then \"$IP6TABLES\" \"$@\"; elif command -v ip6tables >/dev/null 2>&1; then ip6tables \"$@\"; else return 0; fi\n"
                + "}\n"
                + "cleanup_redirects() {\n"
                + "  log_msg 'cleanup guard removing stale DNS redirect rules'\n"
                + "  ipt -D OUTPUT -m mark --mark " + DAEMON_SOCKET_MARK + " -j ACCEPT >/dev/null 2>&1 || true\n"
                + "  ip6t -D OUTPUT -m mark --mark " + DAEMON_SOCKET_MARK + " -j ACCEPT >/dev/null 2>&1 || true\n"
                + "  ipt -D OUTPUT -j \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  ipt -F \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  ipt -X \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  ip6t -D OUTPUT -j \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  ip6t -F \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  ip6t -X \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -D OUTPUT -p udp --dport 53 -j \"$CHAIN4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -D OUTPUT -p tcp --dport 53 -j \"$CHAIN4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -D PREROUTING -p udp --dport 53 -j \"$PRE4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -D PREROUTING -p tcp --dport 53 -j \"$PRE4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -F \"$CHAIN4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -F \"$PRE4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -X \"$CHAIN4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -X \"$PRE4\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -D OUTPUT -p udp --dport 53 -j \"$CHAIN6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -D OUTPUT -p tcp --dport 53 -j \"$CHAIN6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -D PREROUTING -p udp --dport 53 -j \"$PRE6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -D PREROUTING -p tcp --dport 53 -j \"$PRE6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -F \"$CHAIN6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -F \"$PRE6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -X \"$CHAIN6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -X \"$PRE6\" >/dev/null 2>&1 || true\n"
                + "  if command -v nft >/dev/null 2>&1; then nft delete table ip " + NFT_TABLE_V4 + " >/dev/null 2>&1 || true; nft delete table ip6 " + NFT_TABLE_V6 + " >/dev/null 2>&1 || true; fi\n"
                + "}\n"
                + "stop_daemon() {\n"
                + "  if [ -x \"$SUPERVISOR\" ]; then \"$SUPERVISOR\" stop >> \"$LOG\" 2>&1 || true; fi\n"
                + "  if [ -f \"$PID_FILE\" ]; then kill -TERM \"$(cat \"$PID_FILE\")\" 2>/dev/null || true; fi\n"
                + "  if [ -f \"$SUP_PID\" ]; then kill -TERM \"$(cat \"$SUP_PID\")\" 2>/dev/null || true; fi\n"
                + "  if command -v pidof >/dev/null 2>&1; then for p in $(pidof " + DAEMON_NAME + " 2>/dev/null); do kill -TERM \"$p\" 2>/dev/null || true; done; fi\n"
                + "}\n"
                + "remove_root_copies() {\n"
                + "  for FILE in /data/adb/service.d/" + BOOT_SCRIPT
                + " /su/su.d/" + BOOT_SCRIPT
                + " /system/su.d/" + BOOT_SCRIPT
                + " /system/etc/init.d/" + BOOT_SCRIPT
                + " /data/adb/service.d/" + CLEANUP_SCRIPT
                + " /su/su.d/" + CLEANUP_SCRIPT
                + " /system/su.d/" + CLEANUP_SCRIPT
                + " /system/etc/init.d/" + CLEANUP_SCRIPT
                + "; do [ -e \"$FILE\" ] && rm -f \"$FILE\" 2>/dev/null || true; done\n"
                + "}\n"
                + "# Android does not guarantee that app code runs during its own uninstall.\n"
                + "# This guard lets root clean stale DNS capture state on the next startup.\n"
                + "if app_installed && [ -d \"$DIR\" ] && [ -x \"$SUPERVISOR\" ] && [ -f \"$MARKER\" ]; then\n"
                + "  log_msg 'cleanup guard found active service marker; leaving DNS service installed'\n"
                + "  exit 0\n"
                + "fi\n"
                + "log_msg 'cleanup guard found missing app package or stale service marker; removing DNS service state'\n"
                + "rm -f \"$MARKER\" 2>/dev/null || true\n"
                + "stop_daemon\n"
                + "cleanup_redirects\n"
                + "remove_root_copies\n"
                + "log_msg 'cleanup guard complete'\n";
    }

    private static String buildBootScript(Context context, File dir) {
        String supervisor = new File(dir, SUPERVISOR).getAbsolutePath();
        String marker = new File(dir, ENABLED_MARKER).getAbsolutePath();
        String appLog = new File(dir, BOOT_LOG).getAbsolutePath();
        String markStatus = new File(dir, MARK_STATUS).getAbsolutePath();
        String iptables = Api.getBinaryPath(context, false);
        String ip6tables = Api.getBinaryPath(context, true);
        int port = G.dnsHijackPort(DEFAULT_PORT);
        String ipv6Enabled = G.enableIPv6() ? "1" : "0";
        String packageName = context.getPackageName();

        return "#!/system/bin/sh\n"
                + "AFWALL_DNS_MODULE_SCRIPT_VERSION=" + MAGISK_SCRIPT_VERSION + "\n"
                + "PATH=/system/bin:/system/xbin:/vendor/bin:/sbin:/su/bin:/data/adb/magisk:$PATH\n"
                + "PACKAGE=" + shellQuote(packageName) + "\n"
                + "DIR=" + shellQuote(dir.getAbsolutePath()) + "\n"
                + "SUPERVISOR=" + shellQuote(supervisor) + "\n"
                + "MARKER=" + shellQuote(marker) + "\n"
                + "IPTABLES=" + shellQuote(iptables) + "\n"
                + "IP6TABLES=" + shellQuote(ip6tables) + "\n"
                + "PORT=" + port + "\n"
                + "DAEMON_MARK=" + DAEMON_SOCKET_MARK + "\n"
                + "MARK_STATUS=" + shellQuote(markStatus) + "\n"
                + "IPV6_ENABLED=" + ipv6Enabled + "\n"
                + "APP_LOG=" + shellQuote(appLog) + "\n"
                + "FALLBACK_LOG=/data/local/tmp/" + BOOT_LOG + "\n"
                + "CHAIN4=" + CHAIN_V4 + "\n"
                + "PRE4=" + CHAIN_V4_PRE + "\n"
                + "CHAIN6=" + CHAIN_V6 + "\n"
                + "PRE6=" + CHAIN_V6_PRE + "\n"
                + "FILTER=" + CHAIN_FILTER + "\n"
                + "if [ -d \"$DIR\" ]; then LOG=\"$APP_LOG\"; else LOG=\"$FALLBACK_LOG\"; fi\n"
                + "log_msg() {\n"
                + "  echo \"$(date +%s) $*\" >> \"$LOG\" 2>/dev/null || true\n"
                + "  chmod 644 \"$LOG\" 2>/dev/null || true\n"
                + "}\n"
                + "app_installed() {\n"
                + "  pm path \"$PACKAGE\" >/dev/null 2>&1\n"
                + "}\n"
                + "ipt() {\n"
                + "  if [ -x \"$IPTABLES\" ]; then \"$IPTABLES\" \"$@\"; else iptables \"$@\"; fi\n"
                + "}\n"
                + "ip6t() {\n"
                + "  if [ -x \"$IP6TABLES\" ]; then \"$IP6TABLES\" \"$@\"; elif command -v ip6tables >/dev/null 2>&1; then ip6tables \"$@\"; else return 0; fi\n"
                + "}\n"
                + "cleanup_redirects() {\n"
                + "  log_msg 'DNS boot cleanup removing stale redirect rules'\n"
                + "  ipt -D OUTPUT -m mark --mark \"$DAEMON_MARK\" -j ACCEPT >/dev/null 2>&1 || true\n"
                + "  ip6t -D OUTPUT -m mark --mark \"$DAEMON_MARK\" -j ACCEPT >/dev/null 2>&1 || true\n"
                + "  ipt -D OUTPUT -j \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  ipt -F \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  ipt -X \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  ip6t -D OUTPUT -j \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  ip6t -F \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  ip6t -X \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -D OUTPUT -p udp --dport 53 -j \"$CHAIN4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -D OUTPUT -p tcp --dport 53 -j \"$CHAIN4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -D PREROUTING -p udp --dport 53 -j \"$PRE4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -D PREROUTING -p tcp --dport 53 -j \"$PRE4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -F \"$CHAIN4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -F \"$PRE4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -X \"$CHAIN4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -X \"$PRE4\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -D OUTPUT -p udp --dport 53 -j \"$CHAIN6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -D OUTPUT -p tcp --dport 53 -j \"$CHAIN6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -D PREROUTING -p udp --dport 53 -j \"$PRE6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -D PREROUTING -p tcp --dport 53 -j \"$PRE6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -F \"$CHAIN6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -F \"$PRE6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -X \"$CHAIN6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -X \"$PRE6\" >/dev/null 2>&1 || true\n"
                + "  if command -v nft >/dev/null 2>&1; then nft delete table ip " + NFT_TABLE_V4 + " >/dev/null 2>&1 || true; nft delete table ip6 " + NFT_TABLE_V6 + " >/dev/null 2>&1 || true; fi\n"
                + "}\n"
                + "remove_boot_copy() {\n"
                + "  for FILE in /data/adb/service.d/" + BOOT_SCRIPT
                + " /su/su.d/" + BOOT_SCRIPT
                + " /system/su.d/" + BOOT_SCRIPT
                + " /system/etc/init.d/" + BOOT_SCRIPT
                + " /data/adb/service.d/" + CLEANUP_SCRIPT
                + " /su/su.d/" + CLEANUP_SCRIPT
                + " /system/su.d/" + CLEANUP_SCRIPT
                + " /system/etc/init.d/" + CLEANUP_SCRIPT
                + "; do [ -e \"$FILE\" ] && rm -f \"$FILE\" 2>/dev/null || true; done\n"
                + "}\n"
                + "cleanup_stale_install() {\n"
                + "  log_msg 'DNS boot script found missing app package or app-owned service files; self-cleaning'\n"
                + "  rm -f \"$MARKER\" 2>/dev/null || true\n"
                + "  cleanup_redirects\n"
                + "  remove_boot_copy\n"
                + "}\n"
                + "restore_v4() {\n"
                + buildBootDaemonFilterBypass("ipt")
                + "  ipt -t nat -D OUTPUT -p udp --dport 53 -j \"$CHAIN4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -D OUTPUT -p tcp --dport 53 -j \"$CHAIN4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -D PREROUTING -p udp --dport 53 -j \"$PRE4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -D PREROUTING -p tcp --dport 53 -j \"$PRE4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -N \"$CHAIN4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -N \"$PRE4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -F \"$CHAIN4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -F \"$PRE4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -A \"$CHAIN4\" -o lo -j RETURN >> \"$LOG\" 2>&1\n"
                + buildBootDaemonRecursionBypass("ipt", "$CHAIN4")
                + buildBootOutputRedirectRules("ipt", "$CHAIN4")
                + "  ipt -t nat -A \"$PRE4\" -i lo -j RETURN >> \"$LOG\" 2>&1\n"
                + buildBootPreroutingRedirectRules("ipt", "$PRE4")
                + "  ipt -t nat -I OUTPUT 1 -p udp --dport 53 -j \"$CHAIN4\" >> \"$LOG\" 2>&1\n"
                + "  ipt -t nat -I OUTPUT 1 -p tcp --dport 53 -j \"$CHAIN4\" >> \"$LOG\" 2>&1\n"
                + "  ipt -t nat -I PREROUTING 1 -p udp --dport 53 -j \"$PRE4\" >> \"$LOG\" 2>&1\n"
                + "  ipt -t nat -I PREROUTING 1 -p tcp --dport 53 -j \"$PRE4\" >> \"$LOG\" 2>&1\n"
                + buildBootNftFallbackRestore(false, port)
                + "}\n"
                + "restore_v6() {\n"
                + buildBootDaemonFilterBypass("ip6t")
                + "  ip6t -t nat -D OUTPUT -p udp --dport 53 -j \"$CHAIN6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -D OUTPUT -p tcp --dport 53 -j \"$CHAIN6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -D PREROUTING -p udp --dport 53 -j \"$PRE6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -D PREROUTING -p tcp --dport 53 -j \"$PRE6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -N \"$CHAIN6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -N \"$PRE6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -F \"$CHAIN6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -F \"$PRE6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -A \"$CHAIN6\" -o lo -j RETURN >> \"$LOG\" 2>&1\n"
                + buildBootDaemonRecursionBypass("ip6t", "$CHAIN6")
                + buildBootOutputRedirectRules("ip6t", "$CHAIN6")
                + "  ip6t -t nat -A \"$PRE6\" -i lo -j RETURN >> \"$LOG\" 2>&1\n"
                + buildBootPreroutingRedirectRules("ip6t", "$PRE6")
                + "  ip6t -t nat -I OUTPUT 1 -p udp --dport 53 -j \"$CHAIN6\" >> \"$LOG\" 2>&1\n"
                + "  ip6t -t nat -I OUTPUT 1 -p tcp --dport 53 -j \"$CHAIN6\" >> \"$LOG\" 2>&1\n"
                + "  ip6t -t nat -I PREROUTING 1 -p udp --dport 53 -j \"$PRE6\" >> \"$LOG\" 2>&1\n"
                + "  ip6t -t nat -I PREROUTING 1 -p tcp --dport 53 -j \"$PRE6\" >> \"$LOG\" 2>&1\n"
                + buildBootNftFallbackRestore(true, port)
                + "}\n"
                + "log_msg 'DNS boot restore starting'\n"
                + "sleep 15\n"
                + "if ! app_installed || [ ! -d \"$DIR\" ] || [ ! -x \"$SUPERVISOR\" ] || [ ! -f \"$MARKER\" ]; then cleanup_stale_install; exit 0; fi\n"
                + "if \"$SUPERVISOR\" start >> \"$LOG\" 2>&1; then\n"
                + "  log_msg 'DNS boot restore daemon ready; refreshing redirect rules'\n"
                + "  restore_v4\n"
                + "  if [ \"$IPV6_ENABLED\" = 1 ]; then restore_v6; else log_msg 'DNS boot restore skipped IPv6 redirects because IPv6 is disabled'; fi\n"
                + "  log_msg 'DNS boot restore complete'\n"
                + "else\n"
                + "  log_msg 'DNS boot restore daemon not ready; leaving redirects removed'\n"
                + "  cleanup_redirects\n"
                + "  exit 1\n"
                + "fi\n";
    }

    private static String buildSupervisorScript(Context context, File dir, File daemon) {
        String marker = new File(dir, ENABLED_MARKER).getAbsolutePath();
        String config = new File(dir, CONF).getAbsolutePath();
        String pid = new File(dir, PID).getAbsolutePath();
        String socket = new File(dir, SOCKET).getAbsolutePath();
        String heartbeat = new File(dir, HEARTBEAT).getAbsolutePath();
        String daemonEventLog = new File(dir, DAEMON_EVENT_LOG).getAbsolutePath();
        String log = new File(dir, SUPERVISOR_LOG).getAbsolutePath();
        String supervisorPid = new File(dir, SUPERVISOR_PID).getAbsolutePath();
        String restartCount = new File(dir, RESTART_COUNT).getAbsolutePath();
        String lastExit = new File(dir, LAST_EXIT).getAbsolutePath();
        String markStatus = new File(dir, MARK_STATUS).getAbsolutePath();
        String iptables = Api.getBinaryPath(context, false);
        String ip6tables = Api.getBinaryPath(context, true);
        int port = G.dnsHijackPort(DEFAULT_PORT);
        String ipv6Enabled = G.enableIPv6() ? "1" : "0";
        String packageName = context.getPackageName();

        return "#!/system/bin/sh\n"
                + "AFWALL_DNS_MODULE_SCRIPT_VERSION=" + MAGISK_SCRIPT_VERSION + "\n"
                + "PATH=/system/bin:/system/xbin:/vendor/bin:/sbin:/su/bin:/data/adb/magisk:$PATH\n"
                + "PACKAGE=" + shellQuote(packageName) + "\n"
                + "DIR=" + shellQuote(dir.getAbsolutePath()) + "\n"
                + "DAEMON=" + shellQuote(daemon.getAbsolutePath()) + "\n"
                + "CONF=" + shellQuote(config) + "\n"
                + "PID=" + shellQuote(pid) + "\n"
                + "SOCKET=" + shellQuote(socket) + "\n"
                + "HEARTBEAT=" + shellQuote(heartbeat) + "\n"
                + "DAEMON_LOG=" + shellQuote(daemonEventLog) + "\n"
                + "SUP_PID=" + shellQuote(supervisorPid) + "\n"
                + "MARKER=" + shellQuote(marker) + "\n"
                + "LOG=" + shellQuote(log) + "\n"
                + "RESTARTS=" + shellQuote(restartCount) + "\n"
                + "LAST_EXIT=" + shellQuote(lastExit) + "\n"
                + "IPTABLES=" + shellQuote(iptables) + "\n"
                + "IP6TABLES=" + shellQuote(ip6tables) + "\n"
                + "PORT=" + port + "\n"
                + "DAEMON_MARK=" + DAEMON_SOCKET_MARK + "\n"
                + "MARK_STATUS=" + shellQuote(markStatus) + "\n"
                + "IPV6_ENABLED=" + ipv6Enabled + "\n"
                + "CHAIN4=" + CHAIN_V4 + "\n"
                + "PRE4=" + CHAIN_V4_PRE + "\n"
                + "CHAIN6=" + CHAIN_V6 + "\n"
                + "PRE6=" + CHAIN_V6_PRE + "\n"
                + "FILTER=" + CHAIN_FILTER + "\n"
                + "log_msg() {\n"
                + "  echo \"$(date +%s) $*\" >> \"$LOG\" 2>/dev/null\n"
                + "  chmod 644 \"$LOG\" 2>/dev/null || true\n"
                + "}\n"
                + "daemon_log_msg() {\n"
                + "  echo \"$(date +%s) supervisor $*\" >> \"$DAEMON_LOG\" 2>/dev/null\n"
                + "  chmod 644 \"$DAEMON_LOG\" 2>/dev/null || true\n"
                + "}\n"
                + "app_installed() {\n"
                + "  pm path \"$PACKAGE\" >/dev/null 2>&1\n"
                + "}\n"
                + "ipt() {\n"
                + "  if [ -x \"$IPTABLES\" ]; then \"$IPTABLES\" \"$@\"; elif command -v iptables >/dev/null 2>&1; then iptables \"$@\"; else return 0; fi\n"
                + "}\n"
                + "ip6t() {\n"
                + "  if [ -x \"$IP6TABLES\" ]; then \"$IP6TABLES\" \"$@\"; elif command -v ip6tables >/dev/null 2>&1; then ip6tables \"$@\"; else return 0; fi\n"
                + "}\n"
                + "cleanup_redirects() {\n"
                + "  log_msg 'removing DNS redirect rules'\n"
                + "  ipt -D OUTPUT -m mark --mark " + DAEMON_SOCKET_MARK + " -j ACCEPT >/dev/null 2>&1 || true\n"
                + "  ip6t -D OUTPUT -m mark --mark " + DAEMON_SOCKET_MARK + " -j ACCEPT >/dev/null 2>&1 || true\n"
                + "  ipt -D OUTPUT -j \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  ipt -F \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  ipt -X \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  ip6t -D OUTPUT -j \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  ip6t -F \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  ip6t -X \"$FILTER\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -D OUTPUT -p udp --dport 53 -j \"$CHAIN4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -D OUTPUT -p tcp --dport 53 -j \"$CHAIN4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -D PREROUTING -p udp --dport 53 -j \"$PRE4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -D PREROUTING -p tcp --dport 53 -j \"$PRE4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -F \"$CHAIN4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -F \"$PRE4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -X \"$CHAIN4\" >/dev/null 2>&1 || true\n"
                + "  ipt -t nat -X \"$PRE4\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -D OUTPUT -p udp --dport 53 -j \"$CHAIN6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -D OUTPUT -p tcp --dport 53 -j \"$CHAIN6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -D PREROUTING -p udp --dport 53 -j \"$PRE6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -D PREROUTING -p tcp --dport 53 -j \"$PRE6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -F \"$CHAIN6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -F \"$PRE6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -X \"$CHAIN6\" >/dev/null 2>&1 || true\n"
                + "  ip6t -t nat -X \"$PRE6\" >/dev/null 2>&1 || true\n"
                + "  if command -v nft >/dev/null 2>&1; then nft delete table ip " + NFT_TABLE_V4 + " >/dev/null 2>&1 || true; nft delete table ip6 " + NFT_TABLE_V6 + " >/dev/null 2>&1 || true; fi\n"
                + "}\n"
                + "restore_v4() {\n"
                + buildBootDaemonFilterBypass("ipt")
                + "  ipt -t nat -D OUTPUT -p udp --dport 53 -j \"$CHAIN4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -D OUTPUT -p tcp --dport 53 -j \"$CHAIN4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -D PREROUTING -p udp --dport 53 -j \"$PRE4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -D PREROUTING -p tcp --dport 53 -j \"$PRE4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -N \"$CHAIN4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -N \"$PRE4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -F \"$CHAIN4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -F \"$PRE4\" >/dev/null 2>&1\n"
                + "  ipt -t nat -A \"$CHAIN4\" -o lo -j RETURN >> \"$LOG\" 2>&1\n"
                + buildBootDaemonRecursionBypass("ipt", "$CHAIN4")
                + buildBootOutputRedirectRules("ipt", "$CHAIN4")
                + "  ipt -t nat -A \"$PRE4\" -i lo -j RETURN >> \"$LOG\" 2>&1\n"
                + buildBootPreroutingRedirectRules("ipt", "$PRE4")
                + "  ipt -t nat -I OUTPUT 1 -p udp --dport 53 -j \"$CHAIN4\" >> \"$LOG\" 2>&1\n"
                + "  ipt -t nat -I OUTPUT 1 -p tcp --dport 53 -j \"$CHAIN4\" >> \"$LOG\" 2>&1\n"
                + "  ipt -t nat -I PREROUTING 1 -p udp --dport 53 -j \"$PRE4\" >> \"$LOG\" 2>&1\n"
                + "  ipt -t nat -I PREROUTING 1 -p tcp --dport 53 -j \"$PRE4\" >> \"$LOG\" 2>&1\n"
                + buildBootNftFallbackRestore(false, port)
                + "}\n"
                + "restore_v6() {\n"
                + buildBootDaemonFilterBypass("ip6t")
                + "  ip6t -t nat -D OUTPUT -p udp --dport 53 -j \"$CHAIN6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -D OUTPUT -p tcp --dport 53 -j \"$CHAIN6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -D PREROUTING -p udp --dport 53 -j \"$PRE6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -D PREROUTING -p tcp --dport 53 -j \"$PRE6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -N \"$CHAIN6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -N \"$PRE6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -F \"$CHAIN6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -F \"$PRE6\" >/dev/null 2>&1\n"
                + "  ip6t -t nat -A \"$CHAIN6\" -o lo -j RETURN >> \"$LOG\" 2>&1\n"
                + buildBootDaemonRecursionBypass("ip6t", "$CHAIN6")
                + buildBootOutputRedirectRules("ip6t", "$CHAIN6")
                + "  ip6t -t nat -A \"$PRE6\" -i lo -j RETURN >> \"$LOG\" 2>&1\n"
                + buildBootPreroutingRedirectRules("ip6t", "$PRE6")
                + "  ip6t -t nat -I OUTPUT 1 -p udp --dport 53 -j \"$CHAIN6\" >> \"$LOG\" 2>&1\n"
                + "  ip6t -t nat -I OUTPUT 1 -p tcp --dport 53 -j \"$CHAIN6\" >> \"$LOG\" 2>&1\n"
                + "  ip6t -t nat -I PREROUTING 1 -p udp --dport 53 -j \"$PRE6\" >> \"$LOG\" 2>&1\n"
                + "  ip6t -t nat -I PREROUTING 1 -p tcp --dport 53 -j \"$PRE6\" >> \"$LOG\" 2>&1\n"
                + buildBootNftFallbackRestore(true, port)
                + "}\n"
                + "restore_redirects() {\n"
                + "  log_msg 'restoring DNS redirect rules after daemon ready'\n"
                + "  restore_v4\n"
                + "  if [ \"$IPV6_ENABLED\" = 1 ]; then restore_v6; else log_msg 'DNS watchdog skipped IPv6 redirects because IPv6 is disabled'; fi\n"
                + "}\n"
                + "is_running() {\n"
                + "  [ -f \"$PID\" ] && kill -0 \"$(cat \"$PID\")\" 2>/dev/null\n"
                + "}\n"
                + "heartbeat_ok() {\n"
                + "  [ -f \"$HEARTBEAT\" ] || return 1\n"
                + "  beat=$(cat \"$HEARTBEAT\" 2>/dev/null || echo 0)\n"
                + "  case \"$beat\" in *[!0-9]*|'') return 1 ;; esac\n"
                + "  now=$(date +%s 2>/dev/null || echo 0)\n"
                + "  case \"$now\" in *[!0-9]*|'') return 1 ;; esac\n"
                + "  age=$((now - beat))\n"
                + "  [ \"$age\" -ge 0 ] && [ \"$age\" -le 15 ]\n"
                + "}\n"
                + "# PID alone is not readiness; DNS redirects need listeners and a fresh event-loop heartbeat.\n"
                + "daemon_ready() {\n"
                + "  is_running && [ -S \"$SOCKET\" ] && heartbeat_ok\n"
                + "}\n"
                + "wait_ready() {\n"
                + "  tries=0\n"
                + "  while [ \"$tries\" -lt 8 ]; do\n"
                + "    if daemon_ready; then return 0; fi\n"
                + "    sleep 1\n"
                + "    tries=$((tries + 1))\n"
                + "  done\n"
                + "  return 1\n"
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
                + "  trap 'if [ -f \"$PID\" ]; then kill -TERM \"$(cat \"$PID\")\" 2>/dev/null || true; fi; rm -f \"$SUP_PID\"; exit 0' TERM INT\n"
                + "  log_msg 'watchdog started'\n"
                + "  while [ -f \"$MARKER\" ] && app_installed; do\n"
                + "    if [ ! -x \"$DAEMON\" ]; then\n"
                + "      echo \"$(date +%s) missing_daemon\" > \"$LAST_EXIT\" 2>/dev/null\n"
                + "      log_msg 'daemon binary missing or not executable'\n"
                + "      daemon_log_msg 'daemon binary missing or not executable'\n"
                + "      cleanup_redirects\n"
                + "      sleep 5\n"
                + "      continue\n"
                + "    fi\n"
                + "    rm -f \"$PID\" \"$SOCKET\" \"$HEARTBEAT\" 2>/dev/null || true\n"
                + "    daemon_log_msg 'daemon launch requested'\n"
                + "    \"$DAEMON\" --config \"$CONF\" >> \"$DAEMON_LOG\" 2>&1 &\n"
                + "    daemon_pid=$!\n"
                + "    if ! wait_ready; then\n"
                + "      echo \"$(date +%s) start_not_ready\" > \"$LAST_EXIT\" 2>/dev/null\n"
                + "      log_msg 'daemon did not become ready; restarting'\n"
                + "      daemon_log_msg 'daemon did not become ready; restarting'\n"
                + "      kill -TERM \"$daemon_pid\" 2>/dev/null || true\n"
                + "      if [ -f \"$PID\" ]; then kill -TERM \"$(cat \"$PID\")\" 2>/dev/null || true; fi\n"
                + "      wait \"$daemon_pid\" 2>/dev/null || true\n"
                + "      cleanup_redirects\n"
                + "      increment_restarts\n"
                + "      sleep 2\n"
                + "      continue\n"
                + "    fi\n"
                + "    restore_redirects\n"
                + "    while [ -f \"$MARKER\" ] && app_installed; do\n"
                + "      if ! kill -0 \"$daemon_pid\" 2>/dev/null; then\n"
                + "        wait \"$daemon_pid\" 2>/dev/null\n"
                + "        exit_code=$?\n"
                + "        echo \"$(date +%s) exit=$exit_code\" > \"$LAST_EXIT\" 2>/dev/null\n"
                + "        log_msg \"daemon exited with $exit_code; restarting\"\n"
                + "        daemon_log_msg \"daemon exited with $exit_code; restarting\"\n"
                + "        cleanup_redirects\n"
                + "        increment_restarts\n"
                + "        break\n"
                + "      fi\n"
                + "      if ! daemon_ready; then\n"
                + "        echo \"$(date +%s) heartbeat_stale\" > \"$LAST_EXIT\" 2>/dev/null\n"
                + "        log_msg 'daemon heartbeat stale; restarting'\n"
                + "        daemon_log_msg 'daemon heartbeat stale; restarting'\n"
                + "        kill -TERM \"$daemon_pid\" 2>/dev/null || true\n"
                + "        if [ -f \"$PID\" ]; then kill -TERM \"$(cat \"$PID\")\" 2>/dev/null || true; fi\n"
                + "        sleep 2\n"
                + "        kill -KILL \"$daemon_pid\" 2>/dev/null || true\n"
                + "        wait \"$daemon_pid\" 2>/dev/null || true\n"
                + "        cleanup_redirects\n"
                + "        increment_restarts\n"
                + "        break\n"
                + "      fi\n"
                + "      sleep 5\n"
                + "    done\n"
                + "    if [ ! -f \"$MARKER\" ] || ! app_installed; then\n"
                + "      log_msg 'app package or enable marker missing; stopping DNS daemon'\n"
                + "      daemon_log_msg 'app package or enable marker missing; stopping DNS daemon'\n"
                + "      kill -TERM \"$daemon_pid\" 2>/dev/null || true\n"
                + "      wait \"$daemon_pid\" 2>/dev/null || true\n"
                + "    else\n"
                + "      sleep 2\n"
                + "    fi\n"
                + "  done\n"
                + "  cleanup_redirects\n"
                + "  log_msg 'watchdog stopped'\n"
                + "  rm -f \"$SUP_PID\"\n"
                + "}\n"
                + "start_daemon() {\n"
                + "  if ! app_installed; then\n"
                + "    log_msg 'app package missing; refusing to start DNS daemon'\n"
                + "    daemon_log_msg 'app package missing; refusing to start DNS daemon'\n"
                + "    cleanup_redirects\n"
                + "    exit 1\n"
                + "  fi\n"
                + "  if [ ! -d \"$DIR\" ]; then\n"
                + "    log_msg 'app service directory missing; refusing to start DNS daemon'\n"
                + "    daemon_log_msg 'app service directory missing; refusing to start DNS daemon'\n"
                + "    cleanup_redirects\n"
                + "    exit 1\n"
                + "  fi\n"
                + "  chmod 700 \"$DIR\" 2>/dev/null || true\n"
                + "  chmod 755 \"$DAEMON\" 2>/dev/null || true\n"
                + "  touch \"$DAEMON_LOG\" 2>/dev/null || true\n"
                + "  chmod 644 \"$DAEMON_LOG\" 2>/dev/null || true\n"
                + "  touch \"$MARKER\"\n"
                + "  if daemon_ready; then restore_redirects; exit 0; fi\n"
                + "  if ! is_running; then rm -f \"$PID\" \"$SOCKET\" \"$HEARTBEAT\" 2>/dev/null || true; fi\n"
                + "  if supervisor_running; then\n"
                + "    if wait_ready; then restore_redirects; exit 0; fi\n"
                + "    log_msg 'watchdog already running but daemon is not ready'\n"
                + "    exit 1\n"
                + "  fi\n"
                + "  ( watch_loop ) >/dev/null 2>&1 &\n"
                + "  echo \"$!\" > \"$SUP_PID\" 2>/dev/null\n"
                + "  if wait_ready; then restore_redirects; exit 0; fi\n"
                + "  echo \"$(date +%s) start_not_ready\" > \"$LAST_EXIT\" 2>/dev/null\n"
                + "  log_msg 'daemon did not become ready after start request'\n"
                + "  daemon_log_msg 'daemon did not become ready after start request'\n"
                + "  exit 1\n"
                + "}\n"
                + "stop_daemon() {\n"
                + "  rm -f \"$MARKER\"\n"
                + "  if [ -f \"$PID\" ]; then kill -TERM \"$(cat \"$PID\")\" 2>/dev/null || true; fi\n"
                + "  if [ -f \"$SUP_PID\" ]; then kill -TERM \"$(cat \"$SUP_PID\")\" 2>/dev/null || true; fi\n"
                + "  rm -f \"$SUP_PID\" \"$HEARTBEAT\"\n"
                + "}\n"
                + "case \"$1\" in\n"
                + "  start) start_daemon ;;\n"
                + "  stop) stop_daemon; cleanup_redirects; exit 0 ;;\n"
                + "  restart) stop_daemon; start_daemon ;;\n"
                + "  reload) if ! app_installed; then cleanup_redirects; exit 1; fi; if daemon_ready; then kill -HUP \"$(cat \"$PID\")\" 2>/dev/null; restore_redirects; else start_daemon; fi ;;\n"
                + "  status) \n"
                + "    if app_installed; then echo app_package=installed; else echo app_package=missing; fi\n"
                + "    if is_running; then echo \"daemon=running pid=$(cat \"$PID\")\"; else echo daemon=stopped; fi\n"
                + "    if [ -S \"$SOCKET\" ]; then echo control_socket=ready; else echo control_socket=missing; fi\n"
                + "    if heartbeat_ok; then echo heartbeat=fresh; else echo heartbeat=stale; fi\n"
                + "    echo \"heartbeat_value=$(cat \"$HEARTBEAT\" 2>/dev/null || echo none)\"\n"
                + "    if daemon_ready; then echo readiness=ready; else echo readiness=not_ready; fi\n"
                + "    if supervisor_running; then echo \"watchdog=running pid=$(cat \"$SUP_PID\")\"; else echo watchdog=stopped; fi\n"
                + "    echo \"restart_count=$(cat \"$RESTARTS\" 2>/dev/null || echo 0)\"\n"
                + "    echo \"last_exit=$(cat \"$LAST_EXIT\" 2>/dev/null || echo none)\"\n"
                + "    if app_installed; then\n"
                + "      if daemon_ready || supervisor_running; then exit 0; fi\n"
                + "    fi\n"
                + "    exit 1 ;;\n"
                + "  *) echo \"usage: $0 {start|stop|restart|reload|status}\"; exit 2 ;;\n"
                + "esac\n";
    }

    private static File workDir(Context context) {
        Context appContext = context.getApplicationContext();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            Context deviceContext = appContext.createDeviceProtectedStorageContext();
            if (deviceContext != null) {
                // Root boot scripts can run before credential-protected app data is unlocked.
                // Keep the daemon, config, control socket, and event logs in device-protected
                // storage so boot restore and fail-open cleanup do not depend on user unlock.
                return deviceContext.getDir(WORK_DIR, Context.MODE_PRIVATE);
            }
        }
        return appContext.getDir(WORK_DIR, Context.MODE_PRIVATE);
    }

    private static File legacyCredentialProtectedWorkDir(Context context) {
        if (context == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return null;
        }
        Context appContext = context.getApplicationContext();
        File legacy = new File(appContext.getApplicationInfo().dataDir, "app_" + WORK_DIR);
        if (samePath(legacy, workDir(context))) {
            return null;
        }
        return legacy;
    }

    private static boolean samePath(File first, File second) {
        return first != null && second != null
                && first.getAbsolutePath().equals(second.getAbsolutePath());
    }

    private static String workDirStorageLabel(Context context) {
        if (context == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return "credential_protected";
        }
        return legacyCredentialProtectedWorkDir(context) == null
                ? "credential_protected"
                : "device_protected";
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
