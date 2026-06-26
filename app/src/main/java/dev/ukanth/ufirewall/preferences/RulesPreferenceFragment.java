package dev.ukanth.ufirewall.preferences;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.preference.CheckBoxPreference;
import android.preference.Preference;
import android.preference.PreferenceFragment;
import android.preference.SwitchPreference;

import com.afollestad.materialdialogs.MaterialDialog;

import java.io.File;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dev.ukanth.ufirewall.Api;
import dev.ukanth.ufirewall.R;
import dev.ukanth.ufirewall.dns.DnsBlocklistManager;
import dev.ukanth.ufirewall.dns.DnsHijackManager;
import dev.ukanth.ufirewall.service.RootCommand;
import dev.ukanth.ufirewall.util.G;

public class RulesPreferenceFragment extends PreferenceFragment implements
        SharedPreferences.OnSharedPreferenceChangeListener {

    private static final int REQUEST_DNS_BLOCKLIST_FILE = 5301;
    private Context ctx;


    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Load the preferences from an XML resource
        addPreferencesFromResource(R.xml.rules_preferences);

        try {
            updateRuleStatus();
        } catch (Exception e) {
        }

        //make sure Roaming is disable in Wifi-only Tablets
        if (!Api.isMobileNetworkSupported(getActivity())) {
            CheckBoxPreference roamPreference = (CheckBoxPreference) findPreference("enableRoam");
            roamPreference.setChecked(false);
            roamPreference.setEnabled(false);
        } else {
            CheckBoxPreference roamPreference = (CheckBoxPreference) findPreference("enableRoam");
            roamPreference.setEnabled(true);
        }

        wireDnsBlocklistActions();
    }

    private void wireDnsBlocklistActions() {
        Preference importBlocklist = findPreference("dnsHijackImportBlocklist");
        if (importBlocklist != null) {
            importBlocklist.setOnPreferenceClickListener(preference -> {
                openDnsBlocklistPicker();
                return true;
            });
        }

        Preference updateBlocklists = findPreference("dnsHijackUpdateBlocklists");
        if (updateBlocklists != null) {
            updateBlocklists.setOnPreferenceClickListener(preference -> {
                runDnsBlocklistUpdate();
                return true;
            });
        }

        Preference rollbackBlocklist = findPreference("dnsHijackRollbackBlocklist");
        if (rollbackBlocklist != null) {
            rollbackBlocklist.setOnPreferenceClickListener(preference -> {
                runDnsBlocklistRollback();
                return true;
            });
        }
    }

    private void updateRuleStatus() {
        SwitchPreference input_chain = (SwitchPreference) findPreference("input_chain");
        input_chain.setOnPreferenceChangeListener(new Preference.OnPreferenceChangeListener() {
            @Override
            public boolean onPreferenceChange(Preference preference, Object o) {
                return false;
            }
        });
       /* SwitchPreference output_chain = (SwitchPreference) findPreference("output_chain");
        SwitchPreference forward_chain = (SwitchPreference) findPreference("forward_chain");*/

        SwitchPreference input_chain_v6 = (SwitchPreference) findPreference("input_chain_v6");
        SwitchPreference output_chain_v6 = (SwitchPreference) findPreference("output_chain_v6");
        SwitchPreference forward_chain_v6 = (SwitchPreference) findPreference("forward_chain_v6");

        //ipv6 is not enabled
        if (!G.enableIPv6()) {
            input_chain_v6.setEnabled(false);
            output_chain_v6.setEnabled(false);
            forward_chain_v6.setEnabled(false);
        }

        Api.getChainStatus(ctx,  new RootCommand()
                .setFailureToast(R.string.error_apply)
                .setLogging(true)
                .setCallback(new RootCommand.Callback() {
                    @Override
                    public void cbFunc(RootCommand state) {
                        if (state.exitCode == 0) {
                            StringBuilder result = state.res;
                            if (result != null) {
                                String output = result.toString();

                                final String regexIn = "-P INPUT (\\w+)";
                                final String regexOut = "-P OUTPUT (\\w+)";
                                final String regexFwd = "-P FORWARD (\\w+)";
                                final Pattern pattern = Pattern.compile(regexIn);
                                final Pattern pattern2 = Pattern.compile(regexOut);
                                final Pattern pattern3 = Pattern.compile(regexFwd);

                                final Matcher matcher = pattern.matcher(output);
                                boolean firstTime = true;
                                while (matcher.find()) {
                                    if (firstTime) {
                                        G.ipv4Input(matcher.group(1).equals("ACCEPT"));
                                        firstTime = false;
                                    } else {
                                        G.ipv6Input(matcher.group(1).equals("ACCEPT"));
                                    }
                                }
                                firstTime = true;
                                final Matcher matcher2 = pattern2.matcher(output);
                                while (matcher2.find()) {
                                    if (firstTime) {
                                        G.ipv4Output(matcher2.group(1).equals("ACCEPT"));
                                        firstTime = false;
                                    } else {
                                        G.ipv6Output(matcher2.group(1).equals("ACCEPT"));
                                    }
                                }
                                firstTime = true;
                                final Matcher matcher3 = pattern3.matcher(output);
                                while (matcher3.find()) {
                                    if (firstTime) {
                                        G.ipv4Fwd(matcher3.group(1).equals("ACCEPT"));
                                        firstTime = false;
                                    } else {
                                        G.ipv6Fwd(matcher3.group(1).equals("ACCEPT"));
                                    }
                                }
                            }
                            getPreferenceScreen().removeAll();
                            addPreferencesFromResource(R.xml.rules_preferences);
                        }
                    }
                }));
    }

    @Override
    public void onAttach(Context context) {
        super.onAttach(context);
        ctx = context;
    }

    @Override
    public void onAttach(Activity activity) {
        super.onAttach(activity);
        if(Build.VERSION.SDK_INT < Build.VERSION_CODES.M){
            ctx = activity;
        }
    }

    private void openDnsBlocklistPicker() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("text/*");
        try {
            startActivityForResult(intent, REQUEST_DNS_BLOCKLIST_FILE);
        } catch (ActivityNotFoundException e) {
            Intent fallback = new Intent(Intent.ACTION_GET_CONTENT);
            fallback.addCategory(Intent.CATEGORY_OPENABLE);
            fallback.setType("*/*");
            startActivityForResult(fallback, REQUEST_DNS_BLOCKLIST_FILE);
        }
    }

    private void runDnsBlocklistUpdate() {
        runBlocklistTask(() -> DnsBlocklistManager.updateFromConfiguredUrls(ctx));
    }

    private void runDnsBlocklistRollback() {
        runBlocklistTask(() -> DnsBlocklistManager.restorePrevious(ctx));
    }

    private void runBlocklistTask(BlocklistTask task) {
        new Thread(() -> {
            DnsBlocklistManager.Result result = task.run();
            new Handler(Looper.getMainLooper()).post(() -> handleBlocklistResult(result));
        }).start();
    }

    private void handleBlocklistResult(DnsBlocklistManager.Result result) {
        if (getActivity() == null || result == null) {
            return;
        }
        if (!result.failed) {
            Api.setRulesUpToDate(false);
            if (G.enableDnsHijack()) {
                DnsHijackManager.requestReload(ctx);
            }
            Api.toast(ctx, getString(R.string.dns_hijack_blocklist_active));
        } else {
            Api.toast(ctx, getString(R.string.dns_hijack_blocklist_failed));
        }
        new MaterialDialog.Builder(getActivity())
                .title(result.failed ? R.string.dns_hijack_blocklist_failed : R.string.dns_hijack_blocklist_active)
                .content(result.summary())
                .positiveText(R.string.OK)
                .show();
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_DNS_BLOCKLIST_FILE && resultCode == Activity.RESULT_OK && data != null) {
            Uri uri = data.getData();
            if (uri != null) {
                runBlocklistTask(() -> DnsBlocklistManager.importFromUri(ctx, uri));
            }
        }
    }

    private interface BlocklistTask {
        DnsBlocklistManager.Result run();
    }

    @Override
    public void onResume() {
        super.onResume();
        getPreferenceManager().getSharedPreferences()
                .registerOnSharedPreferenceChangeListener(this);

    }

    @Override
    public void onPause() {
        getPreferenceManager().getSharedPreferences()
                .unregisterOnSharedPreferenceChangeListener(this);
        super.onPause();
    }

    @Override
    public void onSharedPreferenceChanged(SharedPreferences sharedPreferences,
                                          String key) {

        if (key.equals("activeRules")) {
            if (!G.activeRules()) {
                //disable service when there is no active rules
                //stopService(new Intent(PreferencesActivity.this, RootShell.class));
                CheckBoxPreference enableRoam = (CheckBoxPreference) findPreference("enableRoam");
                enableRoam.setChecked(false);
                CheckBoxPreference enableLAN = (CheckBoxPreference) findPreference("enableLAN");
                enableLAN.setChecked(false);
                CheckBoxPreference enableVPN = (CheckBoxPreference) findPreference("enableVPN");
                enableVPN.setChecked(false);
                CheckBoxPreference enableTether = (CheckBoxPreference) findPreference("enableTether");
                enableTether.setChecked(false);
                CheckBoxPreference enableTor = (CheckBoxPreference) findPreference("enableTor");
                enableTor.setChecked(false);
                CheckBoxPreference enableCustomRules = (CheckBoxPreference) findPreference("enableCustomRules");
                enableCustomRules.setChecked(false);
                CheckBoxPreference enableDnsHijack = (CheckBoxPreference) findPreference("enableDnsHijack");
                if (enableDnsHijack != null) {
                    enableDnsHijack.setChecked(false);
                }
                CheckBoxPreference dnsBootPersistence = (CheckBoxPreference) findPreference("dnsHijackBootPersistence");
                if (dnsBootPersistence != null) {
                    dnsBootPersistence.setChecked(false);
                }

                G.enableRoam(false);
                G.enableLAN(false);
                G.enableVPN(false);
                G.enableTether(false);
                G.enableTor(false);
                G.enableCustomRules(false);
                G.enableDnsHijack(false);
                G.dnsHijackBootPersistence(false);

            }
        }

        //do chain apply for ipv4
        switch (key) {
            case "input_chain": {
                String rule = "-P INPUT " + (G.ipv4Input() ? "ACCEPT" : "DROP");
                Api.applyRule(ctx, rule, false, new RootCommand()
                        .setFailureToast(R.string.error_apply)
                        .setCallback(new RootCommand.Callback() {
                            @Override
                            public void cbFunc(RootCommand state) {
                                if (state.exitCode == 0) {
                                } else {
                                }
                            }
                        }));
                break;
            }
            case "output_chain": {
                String rule = "-P OUTPUT " + (G.ipv4Output() ? "ACCEPT" : "DROP");
                Api.applyRule(ctx, rule, false, new RootCommand()
                        .setFailureToast(R.string.error_apply)
                        .setCallback(new RootCommand.Callback() {
                            @Override
                            public void cbFunc(RootCommand state) {
                                if (state.exitCode == 0) {
                                } else {
                                }
                            }
                        }));
                break;
            }
            case "forward_chain": {
                String rule = "-P FORWARD " + (G.ipv4Fwd() ? "ACCEPT" : "DROP");
                Api.applyRule(ctx, rule, false, new RootCommand()
                        .setFailureToast(R.string.error_apply)
                        .setCallback(new RootCommand.Callback() {
                            @Override
                            public void cbFunc(RootCommand state) {
                                if (state.exitCode == 0) {
                                } else {
                                }
                            }
                        }));
                break;
            }
            case "input_chain_v6": {
                String rule = "-P INPUT " + (G.ipv6Input() ? "ACCEPT" : "DROP");
                Api.applyRule(ctx, rule, true, new RootCommand()
                        .setFailureToast(R.string.error_apply)
                        .setCallback(new RootCommand.Callback() {
                            @Override
                            public void cbFunc(RootCommand state) {
                                if (state.exitCode == 0) {
                                } else {
                                }
                            }
                        }));
                break;
            }
            case "output_chain_v6": {
                String rule = "-P OUTPUT " + (G.ipv6Output() ? "ACCEPT" : "DROP");
                Api.applyRule(ctx, rule, true, new RootCommand()
                        .setFailureToast(R.string.error_apply)
                        .setCallback(new RootCommand.Callback() {
                            @Override
                            public void cbFunc(RootCommand state) {
                                if (state.exitCode == 0) {
                                } else {
                                }
                            }
                        }));
                break;
            }
            case "forward_chain_v6": {
                String rule = "-P FORWARD " + (G.ipv6Fwd() ? "ACCEPT" : "DROP");
                Api.applyRule(ctx, rule, true, new RootCommand()
                        .setFailureToast(R.string.error_apply)
                        .setCallback(new RootCommand.Callback() {
                            @Override
                            public void cbFunc(RootCommand state) {
                                if (state.exitCode == 0) {
                                } else {
                                }
                            }
                        }));
                break;
            }
        }

        if (key.equals("enableIPv6"))

        {
            File defaultIP6TablesPath = new File("/system/bin/ip6tables");
            if (!defaultIP6TablesPath.exists()) {
                G.enableIPv6(false);
                CheckBoxPreference enable = (CheckBoxPreference) findPreference("enableIPv6");
                enable.setChecked(false);

                /*CheckBoxPreference block = (CheckBoxPreference) findPreference("blockIPv6");
                block.setChecked(false);
                if (ctx != null) {
                    Api.toast(ctx, getString(R.string.ip6unavailable));
                }*/
            } else {
                switch (key) {
                    case "enableIPv6":
                        CheckBoxPreference block = (CheckBoxPreference) findPreference("controlIPv6");
                        block.setChecked(false);
                        break;
                    case "controlIPv6":
                        CheckBoxPreference allow = (CheckBoxPreference) findPreference("enableIPv6");
                        allow.setChecked(false);
                        break;
                }
            }
        }

        if (key.equals("controlIPv6")) {
            CheckBoxPreference allow = (CheckBoxPreference) findPreference("enableIPv6");
            allow.setChecked(false);
        }

        if (isDnsHijackPreference(key)) {
            Api.setRulesUpToDate(false);
            if (!key.equals("enableDnsHijack") && !key.equals("dnsHijackPort")
                    && !key.equals("dnsHijackBootPersistence") && G.enableDnsHijack()) {
                DnsHijackManager.requestReload(ctx);
            }
        }

    }

    private boolean isDnsHijackPreference(String key) {
        return key != null && (key.equals("enableDnsHijack")
                || key.equals("dnsHijackPort")
                || key.equals("dnsHijackUpstreams")
                || key.equals("dnsHijackFailOpen")
                || key.equals("dnsHijackStrictMode")
                || key.equals("dnsHijackBootPersistence")
                || key.equals("dnsHijackTimeoutMs")
                || key.equals("dnsHijackAllowExact")
                || key.equals("dnsHijackAllowSuffix")
                || key.equals("dnsHijackBlockExact")
                || key.equals("dnsHijackBlockSuffix")
                || key.equals("dnsHijackAllowRegex")
                || key.equals("dnsHijackBlockRegex")
                || key.equals("dnsHijackBlocklistUrls"));
    }
}
