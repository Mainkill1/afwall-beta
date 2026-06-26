package dev.ukanth.ufirewall.activity;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import com.afollestad.materialdialogs.MaterialDialog;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import dev.ukanth.ufirewall.Api;
import dev.ukanth.ufirewall.R;
import dev.ukanth.ufirewall.dns.DnsHijackManager;
import dev.ukanth.ufirewall.util.G;
import dev.ukanth.ufirewall.util.ThemeHelper;

public class DnsQueriesActivity extends AppCompatActivity {

    private static final int MENU_REFRESH = 1;
    private static final int MENU_COPY = 2;
    private static final int MENU_SEARCH = 3;
    private static final int MENU_TOGGLE_HISTORY = 4;
    private static final long REFRESH_MS = 2500L;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final List<DnsHijackManager.QueryEntry> entries = new ArrayList<>();
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
            default:
                return super.onOptionsItemSelected(item);
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
        return time + "  " + entry.action + "  " + entry.domain + "  " + entry.latency;
    }

    private void showQueryActions(DnsHijackManager.QueryEntry entry) {
        if (entry == null || !entry.hasDomain()) {
            return;
        }
        new MaterialDialog.Builder(this)
                .title(entry.domain)
                .items(new CharSequence[]{
                        getString(R.string.dns_query_allow_exact),
                        getString(R.string.dns_query_allow_suffix),
                        getString(R.string.dns_query_temp_allow),
                        getString(R.string.dns_query_block_exact),
                        getString(R.string.dns_query_block_suffix),
                        getString(R.string.dns_query_temp_block)
                })
                .itemsCallback((dialog, view, which, text) -> applyQueryAction(entry, which))
                .negativeText(R.string.Cancel)
                .show();
    }

    private void applyQueryAction(DnsHijackManager.QueryEntry entry, int which) {
        int action;
        switch (which) {
            case 0:
                action = DnsHijackManager.RULE_ALLOW_EXACT;
                break;
            case 1:
                action = DnsHijackManager.RULE_ALLOW_SUFFIX;
                break;
            case 2:
                action = DnsHijackManager.RULE_TEMP_ALLOW;
                break;
            case 3:
                action = DnsHijackManager.RULE_BLOCK_EXACT;
                break;
            case 4:
                action = DnsHijackManager.RULE_BLOCK_SUFFIX;
                break;
            case 5:
                action = DnsHijackManager.RULE_TEMP_BLOCK;
                break;
            default:
                return;
        }
        boolean added = DnsHijackManager.addRuleFromQuery(this, entry, action);
        Api.setRulesUpToDate(false);
        Api.toast(this, getString(added ? R.string.dns_query_rule_added : R.string.dns_query_rule_exists));
        loadQueries(false);
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

    private String buildTextDump() {
        StringBuilder dump = new StringBuilder();
        for (DnsHijackManager.QueryEntry entry : entries) {
            dump.append(entry.displayLine()).append('\n');
        }
        return dump.toString();
    }
}
