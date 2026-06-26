package dev.ukanth.ufirewall.activity;

import android.content.Context;
import android.os.Bundle;
import android.view.MenuItem;
import android.view.SubMenu;

import dev.ukanth.ufirewall.Api;
import dev.ukanth.ufirewall.R;
import dev.ukanth.ufirewall.dns.DnsHijackManager;
import dev.ukanth.ufirewall.service.RootCommand;

public class DiagnosticsActivity extends RulesActivity {

    private static final int MENU_DNS_RELOAD = 101;
    private static final int MENU_DNS_RESTART = 102;
    private static final int MENU_DNS_STOP = 103;
    private static final int MENU_DNS_REPAIR = 104;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTitle(getString(R.string.log_hub_diagnostics));
    }

    @Override
    protected void populateMenu(SubMenu sub) {
        super.populateMenu(sub);
        sub.add(0, MENU_DNS_REPAIR, 0, R.string.dns_diagnostics_repair).setIcon(R.drawable.ic_apply_menu);
        sub.add(0, MENU_DNS_RELOAD, 0, R.string.dns_diagnostics_reload).setIcon(R.drawable.ic_refresh);
        sub.add(0, MENU_DNS_RESTART, 0, R.string.dns_diagnostics_restart).setIcon(R.drawable.ic_apply_menu);
        sub.add(0, MENU_DNS_STOP, 0, R.string.dns_diagnostics_stop).setIcon(R.drawable.ic_clearlog);
    }

    @Override
    protected void populateData(final Context ctx) {
        result = new StringBuilder();
        updateLoadingState(getString(R.string.loading_network_info));
        appendNetworkInterfaces(ctx);
    }

    @Override
    protected boolean includeApplicationLog() {
        return false;
    }

    @Override
    protected void appendIfconfig(final Context ctx) {
        writeHeading(result, true, "ifconfig");
        updateLoadingState(getString(R.string.loading_system_info));
        Api.runIfconfig(ctx, new RootCommand()
                .setLogging(true)
                .setCallback(new RootCommand.Callback() {
                    public void cbFunc(RootCommand state) {
                        result.append(state.res);
                        appendDnsDiagnostics(ctx);
                    }
                }));
    }

    private void appendDnsDiagnostics(final Context ctx) {
        writeHeading(result, true, getString(R.string.dns_diagnostics_title));
        result.append(DnsHijackManager.collectLocalDiagnostics(ctx));
        updateLoadingState(getString(R.string.dns_diagnostics_loading));
        new RootCommand()
                .setLogging(true)
                .setReopenShell(true)
                .setCallback(new RootCommand.Callback() {
                    @Override
                    public void cbFunc(RootCommand state) {
                        result.append("\n[root checks]\n");
                        if (state.res != null) {
                            result.append(state.res);
                        } else {
                            result.append("No root diagnostic output.\n");
                        }
                        appendSystemInfo(ctx);
                    }
                })
                .run(ctx, DnsHijackManager.buildRootDiagnosticsCommands(ctx));
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case MENU_DNS_REPAIR:
                runDnsRepair();
                return true;
            case MENU_DNS_RELOAD:
                runDnsAction("reload", getString(R.string.dns_diagnostics_reload_queued));
                return true;
            case MENU_DNS_RESTART:
                runDnsAction("restart", getString(R.string.dns_diagnostics_restart_queued));
                return true;
            case MENU_DNS_STOP:
                runDnsAction("stop", getString(R.string.dns_diagnostics_stop_queued));
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }

    private void runDnsRepair() {
        String successMessage = getString(R.string.dns_diagnostics_repair_queued);
        updateLoadingState(successMessage);
        DnsHijackManager.repairDnsProtection(this, new RootCommand.Callback() {
            @Override
            public void cbFunc(RootCommand state) {
                runOnUiThread(() -> {
                    if (state.exitCode == 0) {
                        Api.toast(DiagnosticsActivity.this, successMessage);
                    } else {
                        Api.toast(DiagnosticsActivity.this, getString(R.string.error_apply));
                    }
                    populateData(DiagnosticsActivity.this);
                });
            }
        });
    }

    private void runDnsAction(String action, String successMessage) {
        updateLoadingState(successMessage);
        DnsHijackManager.runSupervisorAction(this, action, new RootCommand.Callback() {
            @Override
            public void cbFunc(RootCommand state) {
                runOnUiThread(() -> {
                    if (state.exitCode == 0) {
                        Api.toast(DiagnosticsActivity.this, successMessage);
                    } else {
                        Api.toast(DiagnosticsActivity.this, getString(R.string.error_apply));
                    }
                    populateData(DiagnosticsActivity.this);
                });
            }
        });
    }
}
