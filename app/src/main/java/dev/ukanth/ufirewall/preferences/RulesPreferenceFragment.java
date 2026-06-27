package dev.ukanth.ufirewall.preferences;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
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
import java.util.ArrayList;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dev.ukanth.ufirewall.Api;
import dev.ukanth.ufirewall.R;
import dev.ukanth.ufirewall.broadcast.DnsBlocklistUpdateReceiver;
import dev.ukanth.ufirewall.dns.DnsBlocklistManager;
import dev.ukanth.ufirewall.dns.DnsHijackManager;
import dev.ukanth.ufirewall.service.RootCommand;
import dev.ukanth.ufirewall.util.ApplicationErrorLog;
import dev.ukanth.ufirewall.util.G;

public class RulesPreferenceFragment extends PreferenceFragment implements
        SharedPreferences.OnSharedPreferenceChangeListener {

    private static final int REQUEST_DNS_BLOCKLIST_FILE = 5301;
    private Context ctx;
    private boolean suppressDnsLifecycle;


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
        wireDnsServiceActions();
    }

    private void wireDnsServiceActions() {
        Preference repairService = findPreference("dnsHijackRepairService");
        if (repairService != null) {
            repairService.setOnPreferenceClickListener(preference -> {
                repairDnsService();
                return true;
            });
        }

        Preference removeService = findPreference("dnsHijackRemoveService");
        if (removeService != null) {
            removeService.setOnPreferenceClickListener(preference -> {
                confirmRemoveDnsService();
                return true;
            });
        }
    }

    private void wireDnsBlocklistActions() {
        Preference importBlocklist = findPreference("dnsHijackImportBlocklist");
        if (importBlocklist != null) {
            importBlocklist.setOnPreferenceClickListener(preference -> {
                openDnsBlocklistPicker();
                return true;
            });
        }

        Preference pasteBlocklist = findPreference("dnsHijackPasteBlocklist");
        if (pasteBlocklist != null) {
            pasteBlocklist.setOnPreferenceClickListener(preference -> {
                showDnsBlocklistPasteDialog();
                return true;
            });
        }

        Preference blocklistPresets = findPreference("dnsHijackBlocklistPresets");
        if (blocklistPresets != null) {
            blocklistPresets.setOnPreferenceClickListener(preference -> {
                showDnsBlocklistPresetDialog();
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

        Preference benchmarkUpstreams = findPreference("dnsHijackBenchmarkUpstreams");
        if (benchmarkUpstreams != null) {
            benchmarkUpstreams.setOnPreferenceClickListener(preference -> {
                runDnsUpstreamBenchmark();
                return true;
            });
        }

        Preference upstreamProviders = findPreference("dnsHijackUpstreamProviders");
        if (upstreamProviders != null) {
            upstreamProviders.setOnPreferenceClickListener(preference -> {
                showDnsUpstreamProviderDialog();
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

        Preference saveProfilePolicy = findPreference("dnsHijackSaveProfilePolicy");
        if (saveProfilePolicy != null) {
            saveProfilePolicy.setOnPreferenceClickListener(preference -> {
                saveDnsProfilePolicy();
                return true;
            });
        }

        Preference clearProfilePolicy = findPreference("dnsHijackClearProfilePolicy");
        if (clearProfilePolicy != null) {
            clearProfilePolicy.setOnPreferenceClickListener(preference -> {
                clearDnsProfilePolicy();
                return true;
            });
        }

        Preference profilePresets = findPreference("dnsHijackProfilePresets");
        if (profilePresets != null) {
            profilePresets.setOnPreferenceClickListener(preference -> {
                showDnsProfilePresetDialog();
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
                            wireDnsBlocklistActions();
                            wireDnsServiceActions();
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

    private void showDnsBlocklistPasteDialog() {
        if (getActivity() == null) {
            return;
        }
        new MaterialDialog.Builder(getActivity())
                .title(R.string.dns_hijack_paste_blocklist_title)
                .input(getString(R.string.dns_hijack_paste_blocklist_hint),
                        getClipboardText(), (dialog, input) -> {
                            String text = input == null ? "" : input.toString();
                            runBlocklistTask(() -> DnsBlocklistManager.importFromText(ctx, text));
                        })
                .positiveText(R.string.imports)
                .negativeText(R.string.Cancel)
                .show();
    }

    private String getClipboardText() {
        if (ctx == null) {
            return "";
        }
        ClipboardManager clipboard = (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard == null || !clipboard.hasPrimaryClip() || clipboard.getPrimaryClip() == null
                || clipboard.getPrimaryClip().getItemCount() == 0) {
            return "";
        }
        ClipData.Item item = clipboard.getPrimaryClip().getItemAt(0);
        CharSequence text = item == null ? null : item.coerceToText(ctx);
        return text == null ? "" : text.toString();
    }

    private void showDnsBlocklistPresetDialog() {
        if (getActivity() == null) {
            return;
        }
        String[] names = getResources().getStringArray(R.array.dns_hijack_blocklist_preset_names);
        String[] urls = getResources().getStringArray(R.array.dns_hijack_blocklist_preset_urls);
        new MaterialDialog.Builder(getActivity())
                .title(R.string.dns_hijack_blocklist_presets_title)
                .content(R.string.dns_hijack_blocklist_presets_dialog_summary)
                .items(names)
                .itemsCallbackMultiChoice(selectedPresetIndices(urls), (dialog, which, text) -> {
                    int added = 0;
                    int existing = 0;
                    for (int index : which) {
                        if (index < 0 || index >= urls.length) {
                            continue;
                        }
                        if (G.appendDnsHijackBlocklistUrl(urls[index])) {
                            added++;
                        } else {
                            existing++;
                        }
                    }
                    DnsBlocklistUpdateReceiver.scheduleOrCancel(ctx);
                    showDnsBlocklistPresetResult(added, existing);
                    return true;
                })
                .positiveText(R.string.add)
                .negativeText(R.string.Cancel)
                .show();
    }

    private Integer[] selectedPresetIndices(String[] urls) {
        ArrayList<Integer> selected = new ArrayList<>();
        String configured = G.dnsHijackBlocklistUrls();
        if (configured == null || configured.trim().isEmpty()) {
            return null;
        }
        for (int i = 0; i < urls.length; i++) {
            if (containsConfiguredBlocklistUrl(configured, urls[i])) {
                selected.add(i);
            }
        }
        return selected.isEmpty() ? null : selected.toArray(new Integer[0]);
    }

    private boolean containsConfiguredBlocklistUrl(String configured, String url) {
        String normalizedUrl = url == null ? "" : url.trim().toLowerCase(Locale.US);
        if (normalizedUrl.isEmpty()) {
            return false;
        }
        String[] entries = configured.split("[\\r\\n,]+");
        for (String entry : entries) {
            String normalizedEntry = entry == null ? "" : entry.trim().toLowerCase(Locale.US);
            if (normalizedUrl.equals(normalizedEntry)) {
                return true;
            }
        }
        return false;
    }

    private void showDnsBlocklistPresetResult(int added, int existing) {
        if (getActivity() == null) {
            return;
        }
        new MaterialDialog.Builder(getActivity())
                .title(R.string.dns_hijack_blocklist_presets_title)
                .content(getString(R.string.dns_hijack_blocklist_presets_result,
                        added, existing))
                .positiveText(R.string.OK)
                .show();
    }

    private void showDnsProfilePresetDialog() {
        if (getActivity() == null) {
            return;
        }
        String[] names = getResources().getStringArray(R.array.dns_hijack_profile_preset_names);
        String[] values = getResources().getStringArray(R.array.dns_hijack_profile_preset_values);
        new MaterialDialog.Builder(getActivity())
                .title(R.string.dns_hijack_profile_presets_title)
                .items(names)
                .itemsCallback((dialog, view, which, text) -> {
                    if (which >= 0 && which < values.length) {
                        applyDnsProfilePreset(values[which], text == null ? "" : text.toString());
                    }
                })
                .negativeText(R.string.Cancel)
                .show();
    }

    private void applyDnsProfilePreset(String presetId, String presetName) {
        if (ctx == null) {
            return;
        }
        boolean success;
        boolean profileCopy = true;
        suppressDnsLifecycle = true;
        try {
            success = G.applyDnsHijackProfilePreset(presetId);
            if (success && G.dnsHijackUseProfilePolicy()) {
                profileCopy = G.saveActiveDnsHijackProfilePolicy()
                        && DnsBlocklistManager.copyGlobalBlocklistToActiveProfile(ctx);
            }
        } finally {
            suppressDnsLifecycle = false;
        }
        if (!success || !profileCopy) {
            ApplicationErrorLog.add(ctx, "DNS profile preset failed: " + presetId);
            Api.toast(ctx, getString(R.string.dns_hijack_profile_preset_failed));
            return;
        }
        Api.setRulesUpToDate(false);
        DnsBlocklistUpdateReceiver.scheduleOrCancel(ctx);
        if (G.enableDnsHijack()) {
            DnsHijackManager.requestReload(ctx);
        }
        ApplicationErrorLog.add(ctx, "DNS profile preset applied: " + presetId
                + (G.dnsHijackUseProfilePolicy() ? " with active profile policy" : " globally"));
        Api.toast(ctx, getString(R.string.dns_hijack_profile_preset_applied, presetName));
    }

    private void runDnsBlocklistRollback() {
        runBlocklistTask(() -> DnsBlocklistManager.restorePrevious(ctx));
    }

    private void runDnsUpstreamBenchmark() {
        new Thread(() -> {
            String result = DnsHijackManager.benchmarkUpstreams(ctx);
            new Handler(Looper.getMainLooper()).post(() -> showDnsBenchmarkResult(result));
        }).start();
    }

    private void showDnsUpstreamProviderDialog() {
        if (getActivity() == null) {
            return;
        }
        String[] names = getResources().getStringArray(R.array.dns_hijack_upstream_provider_names);
        String[] values = getResources().getStringArray(R.array.dns_hijack_upstream_provider_values);
        new MaterialDialog.Builder(getActivity())
                .title(R.string.dns_hijack_upstream_providers_title)
                .items(names)
                .itemsCallback((dialog, view, which, text) -> {
                    if (which >= 0 && which < values.length) {
                        applyDnsUpstreamProvider(values[which], text == null ? "" : text.toString());
                    }
                })
                .negativeText(R.string.Cancel)
                .show();
    }

    private void applyDnsUpstreamProvider(String providerId, String providerName) {
        if (ctx == null) {
            return;
        }
        boolean savedNewProfilePolicy = true;
        boolean applied = G.applyDnsHijackUpstreamProvider(providerId);
        if (applied && G.dnsHijackUseProfilePolicy()
                && !G.activeDnsHijackProfilePolicySaved()) {
            savedNewProfilePolicy = G.saveActiveDnsHijackProfilePolicy();
        }
        if (!applied || !savedNewProfilePolicy) {
            ApplicationErrorLog.add(ctx, "DNS upstream provider preset failed: " + providerId);
            Api.toast(ctx, getString(R.string.dns_hijack_upstream_provider_failed));
            return;
        }
        Api.setRulesUpToDate(false);
        if (G.enableDnsHijack()) {
            DnsHijackManager.requestReload(ctx);
        }
        ApplicationErrorLog.add(ctx, "DNS upstream provider preset applied: " + providerId
                + (G.dnsHijackUseProfilePolicy() ? " with active profile policy" : " globally"));
        Api.toast(ctx, getString(R.string.dns_hijack_upstream_provider_applied, providerName));
    }

    private void showDnsBenchmarkResult(String result) {
        if (getActivity() == null) {
            return;
        }
        new MaterialDialog.Builder(getActivity())
                .title(R.string.dns_hijack_benchmark_upstreams_title)
                .content(result == null || result.trim().isEmpty()
                        ? getString(R.string.dns_hijack_benchmark_empty)
                        : result)
                .positiveText(R.string.OK)
                .show();
    }

    private void saveDnsProfilePolicy() {
        boolean saved = G.saveActiveDnsHijackProfilePolicy()
                && DnsBlocklistManager.copyGlobalBlocklistToActiveProfile(ctx);
        handleDnsProfilePolicyResult(saved,
                R.string.dns_hijack_profile_policy_saved);
    }

    private void clearDnsProfilePolicy() {
        handleDnsProfilePolicyResult(G.clearActiveDnsHijackProfilePolicy(),
                R.string.dns_hijack_profile_policy_cleared);
    }

    private void handleDnsProfilePolicyResult(boolean success, int successMessage) {
        if (ctx == null) {
            return;
        }
        if (success) {
            Api.setRulesUpToDate(false);
            DnsBlocklistUpdateReceiver.scheduleOrCancel(ctx);
            if (G.enableDnsHijack()) {
                DnsHijackManager.requestReload(ctx);
            }
            Api.toast(ctx, getString(successMessage));
        } else {
            Api.toast(ctx, getString(R.string.dns_hijack_profile_policy_failed));
        }
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
            DnsBlocklistUpdateReceiver.scheduleOrCancel(ctx);
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
            if (isDnsHijackBlocklistSchedulePreference(key)) {
                DnsBlocklistUpdateReceiver.scheduleOrCancel(ctx);
            }
            if (suppressDnsLifecycle) {
                return;
            }
            if (key.equals("enableDnsHijack")) {
                handleDnsHijackEnableChanged();
                return;
            }
            if (key.equals("dnsHijackBootPersistence")) {
                handleDnsBootPersistenceChanged();
                return;
            }
            if (shouldReloadDnsHijackPreference(key) && G.enableDnsHijack()) {
                DnsHijackManager.requestReload(ctx);
            }
        }

    }

    private void handleDnsHijackEnableChanged() {
        if (ctx == null) {
            return;
        }
        final boolean enabled = G.enableDnsHijack();
        DnsHijackManager.applyDnsProtectionPreference(ctx, enabled, new RootCommand.Callback() {
            @Override
            public void cbFunc(RootCommand state) {
                new Handler(Looper.getMainLooper()).post(() -> {
                    if (state.exitCode == 0) {
                        if (!enabled) {
                            setDnsBootPersistenceChecked(false);
                        }
                        Api.toast(ctx, ctx.getString(enabled
                                ? R.string.dns_hijack_enable_complete
                                : R.string.dns_hijack_disable_complete));
                    } else {
                        setDnsHijackChecked(!enabled);
                        Api.toast(ctx, ctx.getString(enabled
                                ? R.string.dns_hijack_enable_failed
                                : R.string.dns_hijack_disable_failed));
                    }
                });
            }
        });
    }

    private void handleDnsBootPersistenceChanged() {
        if (ctx == null) {
            return;
        }
        final boolean enabled = G.dnsHijackBootPersistence();
        DnsHijackManager.updateBootPersistence(ctx, new RootCommand.Callback() {
            @Override
            public void cbFunc(RootCommand state) {
                new Handler(Looper.getMainLooper()).post(() -> {
                    if (state.exitCode == 0) {
                        Api.toast(ctx, ctx.getString(enabled
                                ? R.string.dns_hijack_boot_persistence_installed
                                : R.string.dns_hijack_boot_persistence_removed));
                    } else {
                        setDnsBootPersistenceChecked(!enabled);
                        Api.toast(ctx, ctx.getString(R.string.dns_hijack_boot_persistence_failed));
                    }
                });
            }
        });
    }

    private void repairDnsService() {
        if (ctx == null) {
            return;
        }
        Api.setRulesUpToDate(false);
        DnsHijackManager.applyDnsProtectionPreference(ctx, true, new RootCommand.Callback() {
            @Override
            public void cbFunc(RootCommand state) {
                new Handler(Looper.getMainLooper()).post(() -> {
                    if (state.exitCode == 0) {
                        setDnsHijackChecked(true);
                        Api.toast(ctx, ctx.getString(R.string.dns_hijack_enable_complete));
                    } else {
                        Api.toast(ctx, ctx.getString(R.string.dns_hijack_enable_failed));
                    }
                });
            }
        });
    }

    private void confirmRemoveDnsService() {
        if (ctx == null || getActivity() == null) {
            return;
        }
        new MaterialDialog.Builder(getActivity())
                .title(R.string.dns_hijack_remove_service_title)
                .content(R.string.dns_hijack_remove_service_confirm)
                .positiveText(R.string.OK)
                .negativeText(android.R.string.cancel)
                .onPositive((dialog, which) -> removeDnsService())
                .show();
    }

    private void removeDnsService() {
        if (ctx == null) {
            return;
        }
        final boolean previousEnabled = G.enableDnsHijack();
        final boolean previousBootPersistence = G.dnsHijackBootPersistence();
        setDnsHijackChecked(false);
        setDnsBootPersistenceChecked(false);
        Api.setRulesUpToDate(false);
        DnsBlocklistUpdateReceiver.scheduleOrCancel(ctx);
        DnsHijackManager.applyDnsProtectionPreference(ctx, false, new RootCommand.Callback() {
            @Override
            public void cbFunc(RootCommand state) {
                new Handler(Looper.getMainLooper()).post(() -> {
                    if (state.exitCode == 0) {
                        Api.toast(ctx, ctx.getString(R.string.dns_hijack_disable_complete));
                    } else {
                        setDnsHijackChecked(previousEnabled);
                        setDnsBootPersistenceChecked(previousBootPersistence);
                        DnsBlocklistUpdateReceiver.scheduleOrCancel(ctx);
                        Api.toast(ctx, ctx.getString(R.string.dns_hijack_disable_failed));
                    }
                });
            }
        });
    }

    private void setDnsHijackChecked(boolean enabled) {
        suppressDnsLifecycle = true;
        G.enableDnsHijack(enabled);
        CheckBoxPreference enableDnsHijack = (CheckBoxPreference) findPreference("enableDnsHijack");
        if (enableDnsHijack != null) {
            enableDnsHijack.setChecked(enabled);
        }
        suppressDnsLifecycle = false;
    }

    private void setDnsBootPersistenceChecked(boolean enabled) {
        suppressDnsLifecycle = true;
        G.dnsHijackBootPersistence(enabled);
        CheckBoxPreference dnsBootPersistence = (CheckBoxPreference) findPreference("dnsHijackBootPersistence");
        if (dnsBootPersistence != null) {
            dnsBootPersistence.setChecked(enabled);
        }
        suppressDnsLifecycle = false;
    }

    private boolean isDnsHijackPreference(String key) {
        return key != null && (key.equals("enableDnsHijack")
                || key.equals("dnsHijackPort")
                || key.equals("dnsHijackUpstreams")
                || key.equals("dnsHijackBootstrapUpstreams")
                || key.equals("dnsHijackSplitUpstreams")
                || key.equals("dnsHijackCaptureUids")
                || key.equals("dnsHijackBypassUids")
                || key.equals("dnsHijackCaptureInterfaces")
                || key.equals("dnsHijackBypassInterfaces")
                || key.equals("dnsHijackFailOpen")
                || key.equals("dnsHijackStrictMode")
                || key.equals("dnsHijackSafeSearch")
                || key.equals("dnsHijackDnssecRequest")
                || key.equals("dnsHijackDnssecAuthRequired")
                || key.equals("dnsHijackBootPersistence")
                || key.equals("dnsHijackTimeoutMs")
                || key.equals("dnsHijackCacheSize")
                || key.equals("dnsHijackStaleCacheSeconds")
                || key.equals("dnsHijackPersistCache")
                || key.equals("dnsHijackQueryLogging")
                || key.equals("dnsHijackPersistQueryLogs")
                || key.equals("dnsHijackAllowExact")
                || key.equals("dnsHijackAllowSuffix")
                || key.equals("dnsHijackBlockExact")
                || key.equals("dnsHijackBlockSuffix")
                || key.equals("dnsHijackAppAllowExact")
                || key.equals("dnsHijackAppBlockExact")
                || key.equals("dnsHijackAppAllowSuffix")
                || key.equals("dnsHijackAppBlockSuffix")
                || key.equals("dnsHijackNetworkAllow")
                || key.equals("dnsHijackNetworkBlock")
                || key.equals("dnsHijackAllowRegex")
                || key.equals("dnsHijackBlockRegex")
                || key.equals("dnsHijackBlocklistUrls")
                || key.equals("dnsHijackScheduledBlocklistUpdates")
                || key.equals("dnsHijackBlocklistUpdateIntervalHours")
                || key.equals("dnsHijackUseProfilePolicy"));
    }

    private boolean isDnsHijackBlocklistSchedulePreference(String key) {
        return key != null && (key.equals("enableDnsHijack")
                || key.equals("dnsHijackBlocklistUrls")
                || key.equals("dnsHijackScheduledBlocklistUpdates")
                || key.equals("dnsHijackBlocklistUpdateIntervalHours")
                || key.equals("dnsHijackUseProfilePolicy"));
    }

    private boolean shouldReloadDnsHijackPreference(String key) {
        return key != null
                && !key.equals("enableDnsHijack")
                && !key.equals("dnsHijackPort")
                && !key.equals("dnsHijackBootPersistence")
                && !key.equals("dnsHijackCaptureUids")
                && !key.equals("dnsHijackBypassUids")
                && !key.equals("dnsHijackCaptureInterfaces")
                && !key.equals("dnsHijackBypassInterfaces")
                && !key.equals("dnsHijackBlocklistUrls")
                && !key.equals("dnsHijackScheduledBlocklistUpdates")
                && !key.equals("dnsHijackBlocklistUpdateIntervalHours");
    }
}
