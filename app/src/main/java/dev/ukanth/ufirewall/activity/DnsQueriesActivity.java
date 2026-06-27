package dev.ukanth.ufirewall.activity;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import com.afollestad.materialdialogs.MaterialDialog;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import dev.ukanth.ufirewall.Api;
import dev.ukanth.ufirewall.R;
import dev.ukanth.ufirewall.dns.DnsHijackManager;
import dev.ukanth.ufirewall.service.RootCommand;
import dev.ukanth.ufirewall.util.ApplicationErrorLog;
import dev.ukanth.ufirewall.util.G;
import dev.ukanth.ufirewall.util.ThemeHelper;

public class DnsQueriesActivity extends AppCompatActivity {

    private static final String TAG = "AFWallDnsQueries";
    private static final int REQUEST_EXPORT_DNS_QUERIES = 50;
    private static final int MENU_REFRESH = 1;
    private static final int MENU_COPY = 2;
    private static final int MENU_SEARCH = 3;
    private static final int MENU_TOGGLE_HISTORY = 4;
    private static final int MENU_EXPORT = 5;
    private static final int QUERY_ACTION_VIEW_APP = 100;
    private static final int QUERY_ACTION_VIEW_RULE = 101;
    private static final int QUERY_ACTION_ENABLE_DNS_CAPTURE = 102;
    private static final int QUERY_ACTION_DISABLE_DNS_CAPTURE = 103;
    private static final long REFRESH_MS = 2500L;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final List<DnsHijackManager.QueryEntry> entries = new ArrayList<>();
    private final Map<Integer, String> uidLabelCache = new HashMap<>();
    private final Map<Integer, String> uidPackageCache = new HashMap<>();
    private ArrayAdapter<String> adapter;
    private TextView status;
    private boolean showHistory;
    private String historyFilter = "";

    private final Runnable autoRefresh = new Runnable() {
        @Override
        public void run() {
            if (!showHistory) {
                loadQueries(false);
                handler.postDelayed(this, REFRESH_MS);
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTheme(G.getSelectedThemeStyle(this));
        setContentView(R.layout.activity_dns_queries);

        Toolbar toolbar = findViewById(R.id.dns_queries_toolbar);
        setSupportActionBar(toolbar);
        setTitle(getString(R.string.dns_queries_title));
        toolbar.setNavigationOnClickListener(v -> finish());
        if (getSupportActionBar() != null) {
            getSupportActionBar().setHomeButtonEnabled(true);
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }
        ThemeHelper.apply(this);

        status = findViewById(R.id.dns_queries_status);
        ListView list = findViewById(R.id.dns_queries_list);
        adapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, new ArrayList<>());
        list.setAdapter(adapter);
        list.setOnItemClickListener((parent, view, position, id) -> showQueryActions(entries.get(position)));
        loadQueries(true);
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (!showHistory) {
            handler.postDelayed(autoRefresh, REFRESH_MS);
        }
    }

    @Override
    protected void onPause() {
        handler.removeCallbacks(autoRefresh);
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        menu.add(0, MENU_REFRESH, 0, R.string.refresh).setIcon(R.drawable.ic_refresh);
        menu.add(0, MENU_SEARCH, 0, R.string.Search).setIcon(R.drawable.ic_search);
        menu.add(0, MENU_TOGGLE_HISTORY, 0,
                showHistory ? R.string.dns_queries_live : R.string.dns_queries_history);
        menu.add(0, MENU_COPY, 0, R.string.copy).setIcon(R.drawable.ic_copy);
        menu.add(0, MENU_EXPORT, 0, R.string.export_to_sd).setIcon(R.drawable.ic_export);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case android.R.id.home:
                finish();
                return true;
            case MENU_REFRESH:
                loadQueries(true);
                return true;
            case MENU_SEARCH:
                showSearchDialog();
                return true;
            case MENU_TOGGLE_HISTORY:
                setHistoryMode(!showHistory);
                return true;
            case MENU_COPY:
                Api.copyToClipboard(this, buildTextDump());
                return true;
            case MENU_EXPORT:
                startQueryExportPicker();
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_EXPORT_DNS_QUERIES && resultCode == Activity.RESULT_OK) {
            exportQueriesToUri(data);
        }
    }

    private void loadQueries(boolean showLoading) {
        if (executor.isShutdown()) {
            return;
        }
        if (showLoading) {
            status.setText(R.string.loading);
        }
        final boolean useHistory = showHistory;
        final String filter = historyFilter;
        executor.execute(() -> {
            List<DnsHijackManager.QueryEntry> latest = useHistory
                    ? DnsHijackManager.getHistoricalQueries(this, filter)
                    : DnsHijackManager.getRecentQueries(this);
            runOnUiThread(() -> updateQueries(latest, useHistory, filter));
        });
    }

    private void updateQueries(List<DnsHijackManager.QueryEntry> latest, boolean history, String filter) {
        entries.clear();
        adapter.clear();
        for (int i = latest.size() - 1; i >= 0; i--) {
            DnsHijackManager.QueryEntry entry = latest.get(i);
            entries.add(entry);
            adapter.add(formatEntry(entry));
        }
        adapter.notifyDataSetChanged();
        if (history) {
            if (filter == null || filter.trim().isEmpty()) {
                status.setText(getString(R.string.dns_queries_history_status, latest.size()));
            } else {
                status.setText(getString(R.string.dns_queries_history_filter_status,
                        latest.size(), filter.trim()));
            }
        } else {
            status.setText(getString(R.string.dns_queries_status, latest.size()));
        }
    }

    private String formatEntry(DnsHijackManager.QueryEntry entry) {
        String time = entry.timestamp > 0
                ? new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date(entry.timestamp * 1000L))
                : "--:--:--";
        return time + "  " + entry.result + "  " + entry.domain + "  " + entry.latency
                + "\n" + entry.transport.toUpperCase(Locale.US) + " " + entry.qtype
                + "  app=" + resolveAppLabel(entry) + "  source=" + entry.source + "  uid=" + entry.uid
                + "  rule=" + entry.rule + "  upstream=" + entry.upstream;
    }

    private void showQueryActions(DnsHijackManager.QueryEntry entry) {
        if (entry == null || !entry.hasDomain()) {
            return;
        }
        List<CharSequence> labels = new ArrayList<>();
        List<Integer> actions = new ArrayList<>();
        addQueryAction(labels, actions, R.string.dns_query_allow_exact,
                DnsHijackManager.RULE_ALLOW_EXACT);
        addQueryAction(labels, actions, R.string.dns_query_allow_suffix,
                DnsHijackManager.RULE_ALLOW_SUFFIX);
        addQueryAction(labels, actions, R.string.dns_query_temp_allow,
                DnsHijackManager.RULE_TEMP_ALLOW);
        int uid = parseQueryUid(entry);
        if (uid >= 0) {
            boolean captured = G.dnsHijackUidCaptured(uid);
            addQueryAction(labels, actions, captured
                            ? R.string.dns_query_disable_dns_capture
                            : R.string.dns_query_enable_dns_capture,
                    captured
                            ? QUERY_ACTION_DISABLE_DNS_CAPTURE
                            : QUERY_ACTION_ENABLE_DNS_CAPTURE);
            addQueryAction(labels, actions, R.string.dns_query_app_allow_exact,
                    DnsHijackManager.RULE_APP_ALLOW_EXACT);
            addQueryAction(labels, actions, R.string.dns_query_app_allow_suffix,
                    DnsHijackManager.RULE_APP_ALLOW_SUFFIX);
        }
        addQueryAction(labels, actions, R.string.dns_query_block_exact,
                DnsHijackManager.RULE_BLOCK_EXACT);
        addQueryAction(labels, actions, R.string.dns_query_block_suffix,
                DnsHijackManager.RULE_BLOCK_SUFFIX);
        addQueryAction(labels, actions, R.string.dns_query_temp_block,
                DnsHijackManager.RULE_TEMP_BLOCK);
        if (uid >= 0) {
            addQueryAction(labels, actions, R.string.dns_query_app_block_exact,
                    DnsHijackManager.RULE_APP_BLOCK_EXACT);
            addQueryAction(labels, actions, R.string.dns_query_app_block_suffix,
                    DnsHijackManager.RULE_APP_BLOCK_SUFFIX);
        }
        addQueryAction(labels, actions, R.string.dns_query_view_rule,
                QUERY_ACTION_VIEW_RULE);
        if (resolveAppPackage(entry) != null) {
            addQueryAction(labels, actions, R.string.dns_query_view_app,
                    QUERY_ACTION_VIEW_APP);
        }
        new MaterialDialog.Builder(this)
                .title(entry.domain)
                .items(labels)
                .itemsCallback((dialog, view, which, text) -> applyQueryAction(entry, actions.get(which)))
                .negativeText(R.string.Cancel)
                .show();
    }

    private void addQueryAction(List<CharSequence> labels, List<Integer> actions,
                                int labelRes, int action) {
        labels.add(getString(labelRes));
        actions.add(action);
    }

    private void applyQueryAction(DnsHijackManager.QueryEntry entry, int actionId) {
        int action;
        if (actionId == QUERY_ACTION_VIEW_APP) {
            openQueryApp(entry);
            return;
        }
        if (actionId == QUERY_ACTION_VIEW_RULE) {
            showRuleDetails(entry);
            return;
        }
        if (actionId == QUERY_ACTION_ENABLE_DNS_CAPTURE
                || actionId == QUERY_ACTION_DISABLE_DNS_CAPTURE) {
            updateQueryAppDnsCapture(entry, actionId == QUERY_ACTION_ENABLE_DNS_CAPTURE);
            return;
        }
        switch (actionId) {
            case DnsHijackManager.RULE_ALLOW_EXACT:
                action = DnsHijackManager.RULE_ALLOW_EXACT;
                break;
            case DnsHijackManager.RULE_ALLOW_SUFFIX:
                action = DnsHijackManager.RULE_ALLOW_SUFFIX;
                break;
            case DnsHijackManager.RULE_TEMP_ALLOW:
                action = DnsHijackManager.RULE_TEMP_ALLOW;
                break;
            case DnsHijackManager.RULE_APP_ALLOW_EXACT:
                action = DnsHijackManager.RULE_APP_ALLOW_EXACT;
                break;
            case DnsHijackManager.RULE_APP_ALLOW_SUFFIX:
                action = DnsHijackManager.RULE_APP_ALLOW_SUFFIX;
                break;
            case DnsHijackManager.RULE_BLOCK_EXACT:
                action = DnsHijackManager.RULE_BLOCK_EXACT;
                break;
            case DnsHijackManager.RULE_BLOCK_SUFFIX:
                action = DnsHijackManager.RULE_BLOCK_SUFFIX;
                break;
            case DnsHijackManager.RULE_TEMP_BLOCK:
                action = DnsHijackManager.RULE_TEMP_BLOCK;
                break;
            case DnsHijackManager.RULE_APP_BLOCK_EXACT:
                action = DnsHijackManager.RULE_APP_BLOCK_EXACT;
                break;
            case DnsHijackManager.RULE_APP_BLOCK_SUFFIX:
                action = DnsHijackManager.RULE_APP_BLOCK_SUFFIX;
                break;
            default:
                return;
        }
        boolean added = DnsHijackManager.addRuleFromQuery(this, entry, action);
        Api.setRulesUpToDate(false);
        Api.toast(this, getString(added ? R.string.dns_query_rule_added : R.string.dns_query_rule_exists));
        loadQueries(false);
    }

    private void showRuleDetails(DnsHijackManager.QueryEntry entry) {
        String timestamp = entry.timestamp > 0
                ? new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
                .format(new Date(entry.timestamp * 1000L))
                : "unknown";
        StringBuilder details = new StringBuilder();
        details.append("Time: ").append(timestamp).append('\n');
        details.append("Domain: ").append(entry.domain).append('\n');
        details.append("Decision: ").append(entry.result).append('\n');
        details.append("Rule source: ").append(entry.rule).append('\n');
        details.append("Action: ").append(entry.action).append('\n');
        details.append("Query type: ").append(entry.qtype).append('\n');
        details.append("Transport: ").append(entry.transport).append('\n');
        details.append("Source: ").append(entry.source).append('\n');
        details.append("UID: ").append(entry.uid).append('\n');
        details.append("App: ").append(resolveAppLabel(entry)).append('\n');
        details.append("DNS capture: ").append(G.dnsHijackUidCaptured(parseQueryUid(entry))
                ? "enabled" : "disabled").append('\n');
        details.append("Upstream: ").append(entry.upstream).append('\n');
        details.append("Latency: ").append(entry.latency);

        new MaterialDialog.Builder(this)
                .title(R.string.dns_query_rule_details_title)
                .content(details.toString())
                .positiveText(R.string.OK)
                .show();
    }

    private void openQueryApp(DnsHijackManager.QueryEntry entry) {
        String packageName = resolveAppPackage(entry);
        if (packageName == null) {
            Api.toast(this, getString(R.string.dns_query_app_unknown));
            return;
        }
        try {
            Api.showInstalledAppDetails(this, packageName);
        } catch (RuntimeException e) {
            Log.w(TAG, "Unable to open app details for DNS query UID", e);
            Api.toast(this, getString(R.string.dns_query_app_unknown));
        }
    }

    private void updateQueryAppDnsCapture(DnsHijackManager.QueryEntry entry, boolean enabled) {
        int uid = parseQueryUid(entry);
        if (uid < 0) {
            Api.toast(this, getString(R.string.dns_query_app_unknown));
            return;
        }
        boolean changed = G.dnsHijackUidCaptured(uid, enabled);
        if (!changed) {
            Api.toast(this, getString(R.string.dns_query_dns_capture_unchanged));
            return;
        }
        Api.setRulesUpToDate(false);
        int toast = enabled
                ? R.string.dns_query_dns_capture_enabled
                : R.string.dns_query_dns_capture_disabled;
        ApplicationErrorLog.add(this, "DNS capture " + (enabled ? "enabled" : "disabled")
                + " for UID " + uid + " from live query action");
        if (!G.enableDnsHijack()) {
            Api.toast(this, getString(toast));
            loadQueries(false);
            return;
        }
        DnsHijackManager.repairDnsProtection(this, new RootCommand.Callback() {
            @Override
            public void cbFunc(RootCommand state) {
                runOnUiThread(() -> {
                    if (state.exitCode != 0) {
                        ApplicationErrorLog.add(DnsQueriesActivity.this,
                                "DNS capture policy changed for UID " + uid
                                        + " but redirect repair failed");
                    }
                    Api.toast(DnsQueriesActivity.this, getString(state.exitCode == 0
                            ? toast
                            : R.string.error_apply));
                    loadQueries(false);
                });
            }
        });
    }

    private String resolveAppLabel(DnsHijackManager.QueryEntry entry) {
        int uid = parseQueryUid(entry);
        if (uid < 0) {
            return "unknown";
        }
        String cached = uidLabelCache.get(uid);
        if (cached != null) {
            return cached;
        }

        PackageManager packageManager = getPackageManager();
        String[] packages = packageManager.getPackagesForUid(uid);
        if (packages == null || packages.length == 0) {
            String fallback = "uid " + uid;
            uidLabelCache.put(uid, fallback);
            return fallback;
        }

        String label = packages[0];
        try {
            ApplicationInfo info = packageManager.getApplicationInfo(packages[0],
                    PackageManager.GET_META_DATA);
            CharSequence resolved = packageManager.getApplicationLabel(info);
            if (resolved != null && resolved.length() > 0) {
                label = resolved.toString();
            }
        } catch (PackageManager.NameNotFoundException ignored) {
        }
        if (packages.length > 1) {
            label += " +" + (packages.length - 1);
        }
        uidLabelCache.put(uid, label);
        uidPackageCache.put(uid, packages[0]);
        return label;
    }

    private String resolveAppPackage(DnsHijackManager.QueryEntry entry) {
        int uid = parseQueryUid(entry);
        if (uid < 0) {
            return null;
        }
        if (uidPackageCache.containsKey(uid)) {
            return uidPackageCache.get(uid);
        }
        String[] packages = getPackageManager().getPackagesForUid(uid);
        String packageName = packages == null || packages.length == 0 ? null : packages[0];
        uidPackageCache.put(uid, packageName);
        return packageName;
    }

    private int parseQueryUid(DnsHijackManager.QueryEntry entry) {
        if (entry == null || entry.uid == null) {
            return -1;
        }
        try {
            return Integer.parseInt(entry.uid.trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private void setHistoryMode(boolean enabled) {
        showHistory = enabled;
        if (showHistory) {
            handler.removeCallbacks(autoRefresh);
        } else {
            historyFilter = "";
            handler.removeCallbacks(autoRefresh);
            handler.postDelayed(autoRefresh, REFRESH_MS);
        }
        invalidateOptionsMenu();
        loadQueries(true);
    }

    private void showSearchDialog() {
        new MaterialDialog.Builder(this)
                .title(R.string.Search)
                .input(getString(R.string.dns_queries_search_hint), historyFilter, (dialog, input) -> {
                    historyFilter = input == null ? "" : input.toString().trim();
                    showHistory = true;
                    handler.removeCallbacks(autoRefresh);
                    invalidateOptionsMenu();
                    loadQueries(true);
                })
                .negativeText(R.string.Cancel)
                .show();
    }

    private void startQueryExportPicker() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_TITLE, buildExportFilename());
        intent.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                | Intent.FLAG_GRANT_READ_URI_PERMISSION
                | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        try {
            startActivityForResult(intent, REQUEST_EXPORT_DNS_QUERIES);
        } catch (ActivityNotFoundException e) {
            Log.w(TAG, "System export picker unavailable for DNS query export", e);
            Api.copyToClipboard(this, buildTextDump());
            Api.toast(this, getString(R.string.dns_queries_export_picker_missing));
        }
    }

    private void exportQueriesToUri(Intent data) {
        if (data == null || data.getData() == null) {
            Api.toast(this, getString(R.string.export_logs_fail));
            return;
        }
        Uri uri = data.getData();
        takePersistablePermission(data, Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
        try (OutputStream output = getContentResolver().openOutputStream(uri, "wt")) {
            if (output == null) {
                throw new IOException("Unable to open selected export location");
            }
            output.write(buildTextDump().getBytes(StandardCharsets.UTF_8));
            output.flush();
            Api.toast(this, getString(R.string.dns_queries_export_success));
        } catch (IOException | RuntimeException e) {
            Log.e(TAG, "Unable to export DNS queries", e);
            Api.toast(this, getString(R.string.export_logs_fail));
        }
    }

    private void takePersistablePermission(Intent data, int permissionFlag) {
        Uri uri = data.getData();
        if (uri == null) {
            return;
        }
        int flags = data.getFlags() & permissionFlag;
        if (flags == 0) {
            return;
        }
        try {
            getContentResolver().takePersistableUriPermission(uri, flags);
        } catch (SecurityException e) {
            Log.w(TAG, "Unable to persist DNS query export URI permission", e);
        }
    }

    private String buildExportFilename() {
        String timestamp = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss", Locale.US).format(new Date());
        return "afwall-dns-queries-" + timestamp + ".log";
    }

    private String buildTextDump() {
        StringBuilder dump = new StringBuilder();
        for (DnsHijackManager.QueryEntry entry : entries) {
            dump.append(entry.displayLine()).append('\n');
        }
        return dump.toString();
    }
}
