package dev.ukanth.ufirewall.broadcast;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.SystemClock;
import android.util.Log;

import dev.ukanth.ufirewall.Api;
import dev.ukanth.ufirewall.dns.DnsBlocklistManager;
import dev.ukanth.ufirewall.dns.DnsHijackManager;
import dev.ukanth.ufirewall.util.ApplicationErrorLog;
import dev.ukanth.ufirewall.util.G;

public class DnsBlocklistUpdateReceiver extends BroadcastReceiver {

    private static final String TAG = "AFWallDnsBlocklistAlarm";
    private static final String ACTION_UPDATE = "dev.ukanth.ufirewall.action.DNS_BLOCKLIST_UPDATE";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (context == null || intent == null || !ACTION_UPDATE.equals(intent.getAction())) {
            return;
        }

        PendingResult pendingResult = goAsync();
        Context appContext = context.getApplicationContext();
        new Thread(() -> {
            try {
                runScheduledUpdate(appContext);
            } finally {
                pendingResult.finish();
            }
        }, "AFWallDnsBlocklistUpdate").start();
    }

    public static void scheduleOrCancel(Context context) {
        if (context == null) {
            return;
        }
        if (!shouldSchedule()) {
            cancel(context);
            return;
        }

        long interval = G.dnsHijackBlocklistUpdateIntervalHours() * 60L * 60L * 1000L;
        long firstRun = SystemClock.elapsedRealtime() + interval;
        AlarmManager alarmManager = (AlarmManager) context.getApplicationContext()
                .getSystemService(Context.ALARM_SERVICE);
        if (alarmManager == null) {
            ApplicationErrorLog.add(context, "DNS blocklist scheduled updates could not be scheduled: AlarmManager unavailable");
            return;
        }

        alarmManager.setInexactRepeating(AlarmManager.ELAPSED_REALTIME_WAKEUP, firstRun, interval,
                pendingIntent(context));
        ApplicationErrorLog.add(context, "DNS blocklist scheduled updates enabled every "
                + G.dnsHijackBlocklistUpdateIntervalHours() + " hours");
    }

    public static void cancel(Context context) {
        if (context == null) {
            return;
        }
        AlarmManager alarmManager = (AlarmManager) context.getApplicationContext()
                .getSystemService(Context.ALARM_SERVICE);
        if (alarmManager != null) {
            alarmManager.cancel(pendingIntent(context));
        }
    }

    private static void runScheduledUpdate(Context context) {
        if (!shouldSchedule()) {
            cancel(context);
            return;
        }

        ApplicationErrorLog.add(context, "Scheduled DNS blocklist update started");
        try {
            DnsBlocklistManager.Result result = DnsBlocklistManager.updateFromConfiguredUrls(context);
            if (result.failed) {
                ApplicationErrorLog.add(context, "Scheduled DNS blocklist update failed: "
                        + result.message);
                return;
            }

            Api.setRulesUpToDate(false);
            if (G.enableDnsHijack()) {
                DnsHijackManager.requestReload(context);
            }
            ApplicationErrorLog.add(context, "Scheduled DNS blocklist update completed: "
                    + result.message);
        } catch (RuntimeException e) {
            Log.e(TAG, "Scheduled DNS blocklist update crashed", e);
            ApplicationErrorLog.add(context, "Scheduled DNS blocklist update crashed: "
                    + e.getMessage());
        }
    }

    private static boolean shouldSchedule() {
        return G.enableDnsHijack()
                && G.dnsHijackScheduledBlocklistUpdates()
                && !G.dnsHijackBlocklistUrls().trim().isEmpty();
    }

    private static PendingIntent pendingIntent(Context context) {
        Intent intent = new Intent(context.getApplicationContext(), DnsBlocklistUpdateReceiver.class);
        intent.setAction(ACTION_UPDATE);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            flags |= PendingIntent.FLAG_IMMUTABLE;
        }
        return PendingIntent.getBroadcast(context.getApplicationContext(), 0, intent, flags);
    }
}
