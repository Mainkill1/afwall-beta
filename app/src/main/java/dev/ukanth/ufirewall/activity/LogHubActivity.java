package dev.ukanth.ufirewall.activity;

import android.Manifest;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.app.ActivityCompat;
import androidx.core.content.FileProvider;

import com.afollestad.materialdialogs.MaterialDialog;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import dev.ukanth.ufirewall.BuildConfig;
import dev.ukanth.ufirewall.R;
import dev.ukanth.ufirewall.Api;
import dev.ukanth.ufirewall.broadcast.DnsBlocklistUpdateReceiver;
import dev.ukanth.ufirewall.dns.DnsBlocklistManager;
import dev.ukanth.ufirewall.dns.DnsHijackManager;
import dev.ukanth.ufirewall.log.Log;
import dev.ukanth.ufirewall.log.LogInfo;
import dev.ukanth.ufirewall.service.RootCommand;
import dev.ukanth.ufirewall.util.ApplicationErrorLog;
import dev.ukanth.ufirewall.util.FileDialog;
import dev.ukanth.ufirewall.util.G;
import dev.ukanth.ufirewall.util.ThemeHelper;

public class LogHubActivity extends AppCompatActivity {
    private static final int MY_PERMISSIONS_REQUEST_WRITE_STORAGE = 1;
    private static final int EXPORT_BLOCKED_REQUESTS = 0;
    private static final int EXPORT_IPTABLES_IPV4 = 1;
    private static final int EXPORT_IPTABLES_IPV6 = 2;
    private static final int EXPORT_APPLICATION_LOG = 3;
    private static final int EXPORT_APPLICATION_ERRORS = 4;
    private static final int EXPORT_DNS_QUERIES = 5;

    private final ExecutorService dashboardExecutor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private TextView dnsDashboardStatus;
    private TextView dnsDashboardDetails;
    private Button dnsDashboardPauseResume;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        initTheme();
        setContentView(R.layout.log_hub);

        Toolbar toolbar = findViewById(R.id.log_hub_toolbar);
        setSupportActionBar(toolbar);
        setTitle(getString(R.string.log_hub_title));
        toolbar.setNavigationOnClickListener(v -> finish());
        ThemeHelper.apply(this);

        if (getSupportActionBar() != null) {
            getSupportActionBar().setHomeButtonEnabled(true);
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }

        dnsDashboardStatus = findViewById(R.id.log_hub_dns_dashboard_status);
        dnsDashboardDetails = findViewById(R.id.log_hub_dns_dashboard_details);
        dnsDashboardPauseResume = findViewById(R.id.log_hub_dns_dashboard_pause_resume);
        findViewById(R.id.log_hub_dns_dashboard_queries)
                .setOnClickListener(v -> startActivity(new Intent(this, DnsQueriesActivity.class)));
        dnsDashboardPauseResume.setOnClickListener(v -> runDashboardPauseResume());
        findViewById(R.id.log_hub_dns_dashboard_update)
                .setOnClickListener(v -> runDashboardBlocklistUpdate());
        findViewById(R.id.log_hub_dns_dashboard_restart)
                .setOnClickListener(v -> runDashboardDnsRestart());
        findViewById(R.id.log_hub_dns_dashboard_repair)
                .setOnClickListener(v -> runDashboardDnsRepair());
        findViewById(R.id.log_hub_blocked_requests).setOnClickListener(v -> openBlockedRequests());
        findViewById(R.id.log_hub_dns_queries).setOnClickListener(v -> startActivity(new Intent(this, DnsQueriesActivity.class)));
        findViewById(R.id.log_hub_iptables).setOnClickListener(v -> startActivity(new Intent(this, RulesActivity.class)));
        findViewById(R.id.log_hub_diagnostics).setOnClickListener(v -> startActivity(new Intent(this, DiagnosticsActivity.class)));
        findViewById(R.id.log_hub_application_log).setOnClickListener(v -> startActivity(new Intent(this, ApplicationLogActivity.class)));
        findViewById(R.id.log_hub_application_errors).setOnClickListener(v -> startActivity(new Intent(this, ApplicationErrorsActivity.class)));
        findViewById(R.id.log_hub_export_logs).setOnClickListener(v -> showExportLogSelection());
    }

    @Override
    protected void onResume() {
        super.onResume();
        loadDnsDashboard();
    }

    @Override
    protected void onDestroy() {
        dashboardExecutor.shutdownNow();
        super.onDestroy();
    }

    private void openBlockedRequests() {
        Intent intent = new Intent(this, G.oldLogView() ? OldLogActivity.class : LogActivity.class);
        startActivity(intent);
    }

    private void loadDnsDashboard() {
        if (dashboardExecutor.isShutdown() || dnsDashboardStatus == null || dnsDashboardDetails == null) {
            return;
        }
        dnsDashboardStatus.setText(R.string.dns_dashboard_loading);
        dnsDashboardDetails.setText(R.string.dns_dashboard_loading);
        dashboardExecutor.execute(() -> {
            DnsHijackManager.DnsDashboardSnapshot snapshot =
                    DnsHijackManager.getDashboardSnapshot(this);
            mainHandler.post(() -> {
                dnsDashboardStatus.setText(snapshot.statusLine);
                dnsDashboardDetails.setText(snapshot.detailLine);
                if (dnsDashboardPauseResume != null) {
                    dnsDashboardPauseResume.setText(G.enableDnsHijack()
                            ? R.string.dns_dashboard_pause
                            : R.string.dns_dashboard_resume);
                }
                loadDnsRedirectStatus(snapshot.detailLine);
            });
        });
    }

    private void loadDnsRedirectStatus(String baseDetails) {
        if (dnsDashboardDetails == null) {
            return;
        }
        if (!G.enableDnsHijack()) {
            dnsDashboardDetails.setText(baseDetails + "\nRedirect rules: disabled");
            return;
        }
        new RootCommand()
                .setLogging(true)
                .setReopenShell(true)
                .setCallback(new RootCommand.Callback() {
                    @Override
                    public void cbFunc(RootCommand state) {
                        String output = state.res == null ? "" : state.res.toString();
                        String redirectStatus = DnsHijackManager.formatRootRedirectStatus(output);
                        if (state.exitCode != 0) {
                            ApplicationErrorLog.add(LogHubActivity.this,
                                    "DNS dashboard redirect status check failed");
                        } else if (!DnsHijackManager.isRootRedirectStatusHealthy(output)) {
                            ApplicationErrorLog.add(LogHubActivity.this,
                                    "DNS dashboard redirect status needs repair: " + redirectStatus);
                        }
                        mainHandler.post(() -> dnsDashboardDetails.setText(
                                baseDetails + "\n" + redirectStatus));
                    }
                })
                .run(getApplicationContext(), DnsHijackManager.buildRootRedirectStatusCommands(this));
    }

    private void runDashboardPauseResume() {
        boolean pause = G.enableDnsHijack();
        String message = getString(pause
                ? R.string.dns_dashboard_pause_queued
                : R.string.dns_dashboard_resume_queued);
        dnsDashboardStatus.setText(message);
        RootCommand.Callback callback = new RootCommand.Callback() {
            @Override
            public void cbFunc(RootCommand state) {
                mainHandler.post(() -> {
                    if (state.exitCode == 0) {
                        Api.toast(LogHubActivity.this, message);
                        DnsBlocklistUpdateReceiver.scheduleOrCancel(LogHubActivity.this);
                    } else {
                        Api.toast(LogHubActivity.this, getString(R.string.error_apply));
                    }
                    loadDnsDashboard();
                });
            }
        };
        if (pause) {
            DnsHijackManager.pauseDnsProtection(this, callback);
        } else {
            DnsHijackManager.resumeDnsProtection(this, callback);
        }
    }

    private void runDashboardBlocklistUpdate() {
        if (dashboardExecutor.isShutdown()) {
            return;
        }
        dnsDashboardStatus.setText(R.string.dns_hijack_update_blocklists_title);
        dashboardExecutor.execute(() -> {
            DnsBlocklistManager.Result result = DnsBlocklistManager.updateFromConfiguredUrls(this);
            mainHandler.post(() -> handleDashboardBlocklistResult(result));
        });
    }

    private void handleDashboardBlocklistResult(DnsBlocklistManager.Result result) {
        if (result == null) {
            return;
        }
        if (!result.failed) {
            Api.setRulesUpToDate(false);
            if (G.enableDnsHijack()) {
                DnsHijackManager.requestReload(this);
            }
            DnsBlocklistUpdateReceiver.scheduleOrCancel(this);
            Api.toast(this, getString(R.string.dns_hijack_blocklist_active));
        } else {
            Api.toast(this, getString(R.string.dns_hijack_blocklist_failed));
        }
        new MaterialDialog.Builder(this)
                .title(result.failed ? R.string.dns_hijack_blocklist_failed : R.string.dns_hijack_blocklist_active)
                .content(result.summary())
                .positiveText(R.string.OK)
                .show();
        loadDnsDashboard();
    }

    private void runDashboardDnsRepair() {
        String message = getString(R.string.dns_diagnostics_repair_queued);
        dnsDashboardStatus.setText(message);
        DnsHijackManager.repairDnsProtection(this, new RootCommand.Callback() {
            @Override
            public void cbFunc(RootCommand state) {
                mainHandler.post(() -> {
                    if (state.exitCode == 0) {
                        Api.toast(LogHubActivity.this, message);
                    } else {
                        Api.toast(LogHubActivity.this, getString(R.string.error_apply));
                    }
                    loadDnsDashboard();
                });
            }
        });
    }

    private void runDashboardDnsRestart() {
        if (!G.enableDnsHijack()) {
            Api.toast(this, getString(R.string.dns_dashboard_disabled));
            return;
        }
        String message = getString(R.string.dns_diagnostics_restart_queued);
        dnsDashboardStatus.setText(message);
        DnsHijackManager.runSupervisorAction(this, "restart", new RootCommand.Callback() {
            @Override
            public void cbFunc(RootCommand state) {
                mainHandler.post(() -> {
                    if (state.exitCode == 0) {
                        Api.toast(LogHubActivity.this, message);
                    } else {
                        Api.toast(LogHubActivity.this, getString(R.string.error_apply));
                    }
                    loadDnsDashboard();
                });
            }
        });
    }

    private void showExportLogSelection() {
        List<CharSequence> items = new ArrayList<>();
        List<Integer> itemValues = new ArrayList<>();

        items.add(getString(R.string.log_hub_blocked_requests));
        itemValues.add(EXPORT_BLOCKED_REQUESTS);
        items.add(getString(R.string.dns_queries_title));
        itemValues.add(EXPORT_DNS_QUERIES);
        items.add(getString(R.string.export_logs_iptables_ipv4));
        itemValues.add(EXPORT_IPTABLES_IPV4);
        if (G.enableIPv6()) {
            items.add(getString(R.string.export_logs_iptables_ipv6));
            itemValues.add(EXPORT_IPTABLES_IPV6);
        }
        items.add(getString(R.string.application_log_title));
        itemValues.add(EXPORT_APPLICATION_LOG);
        items.add(getString(R.string.application_errors_title));
        itemValues.add(EXPORT_APPLICATION_ERRORS);

        new MaterialDialog.Builder(this)
                .title(R.string.export_logs_title)
                .items(items)
                .itemsCallbackMultiChoice(getDefaultExportSelections(items.size()), (dialog, which, text) -> {
                    if (which == null || which.length == 0) {
                        Api.toast(this, getString(R.string.export_logs_select_one));
                        return false;
                    }
                    showExportDestinationChoice(resolveExportSections(which, itemValues));
                    return true;
                })
                .positiveText(R.string.exports)
                .negativeText(R.string.Cancel)
                .show();
    }

    private Integer[] getDefaultExportSelections(int itemCount) {
        Integer[] selections = new Integer[itemCount];
        for (int i = 0; i < itemCount; i++) {
            selections[i] = i;
        }
        return selections;
    }

    private Integer[] resolveExportSections(Integer[] selectedIndexes, List<Integer> itemValues) {
        Integer[] sections = new Integer[selectedIndexes.length];
        for (int i = 0; i < selectedIndexes.length; i++) {
            sections[i] = itemValues.get(selectedIndexes[i]);
        }
        return sections;
    }

    private void showExportDestinationChoice(Integer[] selectedSections) {
        new MaterialDialog.Builder(this)
                .title(R.string.export_logs_title)
                .items(new CharSequence[]{
                        getString(R.string.send_report),
                        getString(R.string.export_logs_save_to_disk)
                })
                .itemsCallback((dialog, view, which, text) -> {
                    if (which == 0) {
                        sendSelectedLogs(selectedSections);
                    } else {
                        selectExportDirectory(selectedSections);
                    }
                })
                .negativeText(R.string.Cancel)
                .show();
    }

    private void selectExportDirectory(Integer[] selectedSections) {
        File defaultPath = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
                ? new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS), "AFWall")
                : new File(Environment.getExternalStorageDirectory().getAbsolutePath() + "/");
        if (!defaultPath.exists()) {
            defaultPath.mkdirs();
        }

        try {
            FileDialog fileDialog = new FileDialog(this, defaultPath, true);
            fileDialog.setSelectDirectoryOption(true);
            fileDialog.addDirectoryListener(directory -> exportSelectedLogs(directory, selectedSections));
            fileDialog.showDialog();
        } catch (Exception e) {
            exportSelectedLogs(defaultPath, selectedSections);
        }
    }

    private void exportSelectedLogs(File directory, Integer[] selectedSections) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q
                && ActivityCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this,
                    new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},
                    MY_PERMISSIONS_REQUEST_WRITE_STORAGE);
            return;
        }

        ExecutorService executor = Executors.newSingleThreadExecutor();
        executor.execute(() -> writeSelectedLogs(directory, selectedSections));
        executor.shutdown();
    }

    private void sendSelectedLogs(Integer[] selectedSections) {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        executor.execute(() -> {
            String content = buildExportContent(selectedSections);
            File attachment = null;
            if (G.zipLogReports()) {
                attachment = createLogReportZip(content);
            }
            File finalAttachment = attachment;
            new Handler(Looper.getMainLooper()).post(() -> {
                if (G.zipLogReports() && finalAttachment != null) {
                    sendZippedLogReport(finalAttachment);
                } else {
                    sendRawLogReport(content);
                }
            });
        });
        executor.shutdown();
    }

    private void sendRawLogReport(String content) {
        String ver;
        try {
            ver = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (NameNotFoundException e) {
            ver = "???";
        }

        String body = content + "\n\n" + getString(R.string.enter_problem) + "\n\n";
        Intent emailIntent = new Intent(Intent.ACTION_SEND);
        emailIntent.setType("plain/text");
        emailIntent.putExtra(Intent.EXTRA_EMAIL, new String[]{"afwall-report@googlegroups.com"});
        emailIntent.putExtra(Intent.EXTRA_SUBJECT, "AFWall+ problem report - v" + ver);
        emailIntent.putExtra(Intent.EXTRA_TEXT, body);
        try {
            startActivity(Intent.createChooser(emailIntent, getString(R.string.send_mail)));
        } catch (ActivityNotFoundException e) {
            Api.toast(this, getString(R.string.no_email_clients), Toast.LENGTH_LONG);
        }
    }

    private void sendZippedLogReport(File attachment) {
        String ver;
        try {
            ver = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (NameNotFoundException e) {
            ver = "???";
        }

        Uri attachmentUri;
        try {
            attachmentUri = FileProvider.getUriForFile(
                    this,
                    BuildConfig.APPLICATION_ID + ".fileprovider",
                    attachment);
        } catch (IllegalArgumentException e) {
            dev.ukanth.ufirewall.log.Log.e(Api.TAG, "Unable to attach zipped log report", e);
            Api.toast(this, getString(R.string.export_logs_fail), Toast.LENGTH_LONG);
            return;
        }
        Intent emailIntent = new Intent(Intent.ACTION_SEND);
        emailIntent.setType("application/zip");
        emailIntent.putExtra(Intent.EXTRA_EMAIL, new String[]{"afwall-report@googlegroups.com"});
        emailIntent.putExtra(Intent.EXTRA_SUBJECT, "AFWall+ problem report - v" + ver);
        emailIntent.putExtra(Intent.EXTRA_TEXT,
                getString(R.string.log_report_attachment_note) + "\n\n" + getString(R.string.enter_problem) + "\n\n");
        emailIntent.putExtra(Intent.EXTRA_STREAM, attachmentUri);
        emailIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        try {
            startActivity(Intent.createChooser(emailIntent, getString(R.string.send_mail)));
        } catch (ActivityNotFoundException e) {
            Api.toast(this, getString(R.string.no_email_clients), Toast.LENGTH_LONG);
        }
    }

    private File createLogReportZip(String content) {
        try {
            File reportDir = new File(getCacheDir(), "log-reports");
            if (!reportDir.exists()) {
                reportDir.mkdirs();
            }
            String timestamp = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss", Locale.US).format(new Date());
            File zipFile = new File(reportDir, "afwall-logs-" + timestamp + ".zip");
            try (ZipOutputStream zipOutput = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(zipFile)))) {
                ZipEntry entry = new ZipEntry("afwall-logs-" + timestamp + ".log");
                zipOutput.putNextEntry(entry);
                zipOutput.write(content.getBytes(StandardCharsets.UTF_8));
                zipOutput.closeEntry();
            }
            return zipFile;
        } catch (IOException e) {
            dev.ukanth.ufirewall.log.Log.e(Api.TAG, "Unable to create zipped log report", e);
        }
        return null;
    }

    private void writeSelectedLogs(File directory, Integer[] selectedSections) {
        boolean success = false;
        String filename = "";
        try {
            if (!directory.exists()) {
                directory.mkdirs();
            }
            String timestamp = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss", Locale.US).format(new Date());
            File file = new File(directory, "afwall-logs-" + timestamp + ".log");
            FileOutputStream output = new FileOutputStream(file);
            output.write(buildExportContent(selectedSections).getBytes());
            output.flush();
            output.close();
            filename = file.getAbsolutePath();
            success = true;
        } catch (IOException e) {
            dev.ukanth.ufirewall.log.Log.e(Api.TAG, "Unable to export selected logs", e);
        }

        boolean finalSuccess = success;
        String finalFilename = filename;
        new Handler(Looper.getMainLooper()).post(() -> {
            if (finalSuccess) {
                Api.toast(this, getString(R.string.export_rules_success) + finalFilename, Toast.LENGTH_LONG);
            } else {
                Api.toast(this, getString(R.string.export_logs_fail), Toast.LENGTH_LONG);
            }
        });
    }

    private String buildExportContent(Integer[] selectedSections) {
        StringBuilder builder = new StringBuilder();
        for (Integer section : selectedSections) {
            if (section == null) {
                continue;
            }
            switch (section) {
                case EXPORT_BLOCKED_REQUESTS:
                    appendExportSection(builder, getString(R.string.log_hub_blocked_requests),
                            LogInfo.parseLog(this, Api.fetchLogs()));
                    break;
                case EXPORT_IPTABLES_IPV4:
                    appendExportSection(builder, getString(R.string.export_logs_iptables_ipv4),
                            fetchIptablesExport(false));
                    break;
                case EXPORT_IPTABLES_IPV6:
                    appendExportSection(builder, getString(R.string.export_logs_iptables_ipv6),
                            fetchIptablesExport(true));
                    break;
                case EXPORT_APPLICATION_LOG:
                    appendExportSection(builder, getString(R.string.application_log_title), Log.getApplicationLog());
                    break;
                case EXPORT_APPLICATION_ERRORS:
                    String errors = ApplicationErrorLog.get(this);
                    appendExportSection(builder, getString(R.string.application_errors_title),
                            errors.trim().isEmpty() ? getString(R.string.application_errors_empty) : errors);
                    break;
                case EXPORT_DNS_QUERIES:
                    appendExportSection(builder, getString(R.string.dns_queries_title), buildDnsQueryExport());
                    break;
            }
        }
        return builder.toString();
    }

    private String buildDnsQueryExport() {
        StringBuilder dns = new StringBuilder();
        for (DnsHijackManager.QueryEntry entry : DnsHijackManager.getRecentQueries(this)) {
            dns.append(entry.displayLine()).append('\n');
        }
        return dns.toString();
    }

    private String fetchIptablesExport(boolean ipv6) {
        CountDownLatch latch = new CountDownLatch(1);
        StringBuilder rules = new StringBuilder();
        Api.fetchIptablesRules(this, ipv6, new RootCommand()
                .setLogging(true)
                .setReopenShell(true)
                .setCallback(new RootCommand.Callback() {
                    @Override
                    public void cbFunc(RootCommand state) {
                        if (state.res != null) {
                            rules.append(state.res);
                        }
                        latch.countDown();
                    }
                }));
        try {
            if (!latch.await(30, TimeUnit.SECONDS)) {
                return getString(R.string.export_logs_iptables_timeout);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return getString(R.string.export_logs_iptables_interrupted);
        }
        return rules.toString();
    }

    private void appendExportSection(StringBuilder builder, String title, String content) {
        if (builder.length() > 0) {
            builder.append("\n\n");
        }
        builder.append("==== ").append(title).append(" ====\n\n");
        if (content == null || content.trim().isEmpty()) {
            builder.append(getString(R.string.no_data_available));
        } else {
            builder.append(content.trim());
        }
        builder.append("\n");
    }

    private void initTheme() {
        setTheme(G.getSelectedThemeStyle(this));
    }
}
