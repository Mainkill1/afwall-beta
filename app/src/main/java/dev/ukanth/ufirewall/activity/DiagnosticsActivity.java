package dev.ukanth.ufirewall.activity;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.MenuItem;
import android.view.SubMenu;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import dev.ukanth.ufirewall.Api;
import dev.ukanth.ufirewall.R;
import dev.ukanth.ufirewall.dns.DnsHijackManager;
import dev.ukanth.ufirewall.service.RootCommand;
import dev.ukanth.ufirewall.util.ApplicationErrorLog;

public class DiagnosticsActivity extends RulesActivity {

    private static final int REQUEST_EXPORT_DNS_DIAGNOSTICS = 5060;
    private static final int MENU_DNS_RELOAD = 101;
    private static final int MENU_DNS_RESTART = 102;
    private static final int MENU_DNS_STOP = 103;
    private static final int MENU_DNS_REPAIR = 104;
    private static final int MENU_DNS_EXPORT = 105;

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
        sub.add(0, MENU_DNS_EXPORT, 0, R.string.dns_diagnostics_export).setIcon(R.drawable.ic_export);
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
            case MENU_DNS_EXPORT:
                startDnsDiagnosticsExportPicker();
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_EXPORT_DNS_DIAGNOSTICS && resultCode == Activity.RESULT_OK) {
            exportDnsDiagnosticsToUri(data);
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

    private void startDnsDiagnosticsExportPicker() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_TITLE, buildDnsDiagnosticsExportFilename());
        intent.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                | Intent.FLAG_GRANT_READ_URI_PERMISSION
                | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        try {
            startActivityForResult(intent, REQUEST_EXPORT_DNS_DIAGNOSTICS);
        } catch (ActivityNotFoundException e) {
            Api.copyToClipboard(this, currentDnsDiagnosticsText());
            Api.toast(this, getString(R.string.dns_diagnostics_export_picker_missing));
            ApplicationErrorLog.add(this,
                    "DNS diagnostics export picker unavailable; report copied to clipboard");
        }
    }

    private void exportDnsDiagnosticsToUri(Intent data) {
        if (data == null || data.getData() == null) {
            Api.toast(this, getString(R.string.export_logs_fail));
            return;
        }
        Uri uri = data.getData();
        takePersistablePermission(data, Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
        try (OutputStream output = getContentResolver().openOutputStream(uri, "wt")) {
            if (output == null) {
                throw new IOException("Unable to open selected diagnostics export location");
            }
            output.write(currentDnsDiagnosticsText().getBytes(StandardCharsets.UTF_8));
            output.flush();
            Api.toast(this, getString(R.string.dns_diagnostics_export_success));
            ApplicationErrorLog.add(this, "DNS diagnostics exported through system picker");
        } catch (IOException | RuntimeException e) {
            Api.toast(this, getString(R.string.export_logs_fail));
            ApplicationErrorLog.add(this, "DNS diagnostics export failed: " + e.getMessage());
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
            ApplicationErrorLog.add(this,
                    "DNS diagnostics export URI permission could not be persisted: "
                            + e.getMessage());
        }
    }

    private String buildDnsDiagnosticsExportFilename() {
        String timestamp = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss", Locale.US)
                .format(new Date());
        return "afwall-dns-diagnostics-" + timestamp + ".log";
    }

    private String currentDnsDiagnosticsText() {
        if (dataText != null && !dataText.trim().isEmpty()) {
            return dataText;
        }
        return result == null ? "" : result.toString();
    }
}
