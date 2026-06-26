package dev.ukanth.ufirewall.dns;

import android.content.Context;
import android.net.Uri;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

import dev.ukanth.ufirewall.util.ApplicationErrorLog;
import dev.ukanth.ufirewall.util.G;

public final class DnsBlocklistManager {

    private static final String TAG = "AFWallDnsBlocklists";
    private static final String DIR = "dnsd_blocklists";
    private static final String EXACT_FILE = "block_exact.txt";
    private static final String SUFFIX_FILE = "block_suffix.txt";
    private static final String EXACT_BACKUP = "block_exact.previous.txt";
    private static final String SUFFIX_BACKUP = "block_suffix.previous.txt";
    private static final String META_FILE = "metadata.txt";
    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
            "^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$");

    private DnsBlocklistManager() {
    }

    public static Result importFromUri(Context context, Uri uri) {
        Result result = new Result("file import");
        try (InputStream input = context.getContentResolver().openInputStream(uri)) {
            if (input == null) {
                result.failed = true;
                result.message = "Unable to open selected blocklist";
                return result;
            }
            parseStream(input, result);
            activate(context, result);
            return result;
        } catch (IOException e) {
            result.failed = true;
            result.message = e.getMessage();
            Log.e(TAG, "DNS blocklist import failed", e);
            ApplicationErrorLog.add(context, "DNS blocklist import failed: " + e.getMessage());
            return result;
        }
    }

    public static Result importFromText(Context context, String text) {
        Result result = new Result("paste import");
        if (text == null || text.trim().isEmpty()) {
            result.failed = true;
            result.message = "No DNS blocklist text was provided";
            return result;
        }
        try (InputStream input = new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8))) {
            parseStream(input, result);
            activate(context, result);
            return result;
        } catch (IOException e) {
            result.failed = true;
            result.message = e.getMessage();
            Log.e(TAG, "DNS blocklist paste import failed", e);
            ApplicationErrorLog.add(context, "DNS blocklist paste import failed: " + e.getMessage());
            return result;
        }
    }

    public static Result updateFromConfiguredUrls(Context context) {
        Result result = new Result("URL update");
        String raw = G.dnsHijackBlocklistUrls();
        if (raw.trim().isEmpty()) {
            result.failed = true;
            result.message = "No DNS blocklist URLs configured";
            return result;
        }

        String[] urls = raw.split("[\\r\\n,]+");
        for (String item : urls) {
            String url = item == null ? "" : item.trim();
            if (url.isEmpty() || url.startsWith("#")) {
                continue;
            }
            result.sources++;
            downloadAndParse(url, result);
        }

        if (result.sources == 0) {
            result.failed = true;
            result.message = "No valid DNS blocklist URLs configured";
            return result;
        }
        if (!result.hasRules()) {
            result.failed = true;
            result.message = "No valid DNS blocklist entries found";
            return result;
        }

        try {
            activate(context, result);
        } catch (IOException e) {
            result.failed = true;
            result.message = e.getMessage();
            Log.e(TAG, "DNS blocklist URL activation failed", e);
            ApplicationErrorLog.add(context, "DNS blocklist URL activation failed: " + e.getMessage());
        }
        return result;
    }

    public static Result restorePrevious(Context context) {
        Result result = new Result("rollback");
        File dir = blocklistDir(context);
        File exactBackup = new File(dir, EXACT_BACKUP);
        File suffixBackup = new File(dir, SUFFIX_BACKUP);
        if (!exactBackup.exists() && !suffixBackup.exists()) {
            result.failed = true;
            result.message = "No previous DNS blocklist backup exists";
            return result;
        }
        try {
            copyIfExists(exactBackup, new File(dir, EXACT_FILE));
            copyIfExists(suffixBackup, new File(dir, SUFFIX_FILE));
            writeMetadata(context, "rollback", countLines(new File(dir, EXACT_FILE)),
                    countLines(new File(dir, SUFFIX_FILE)), 0, 0, 0);
            result.message = "Restored previous DNS blocklist";
            return result;
        } catch (IOException e) {
            result.failed = true;
            result.message = e.getMessage();
            Log.e(TAG, "DNS blocklist rollback failed", e);
            ApplicationErrorLog.add(context, "DNS blocklist rollback failed: " + e.getMessage());
            return result;
        }
    }

    public static String getSummary(Context context) {
        File meta = new File(blocklistDir(context), META_FILE);
        if (!meta.exists()) {
            return "No imported DNS blocklist is active.";
        }
        try (FileInputStream input = new FileInputStream(meta)) {
            byte[] data = new byte[(int) Math.min(meta.length(), 8192)];
            int read = input.read(data);
            return read <= 0 ? "No imported DNS blocklist is active." : new String(data, 0, read, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "Unable to read DNS blocklist metadata: " + e.getMessage();
        }
    }

    public static boolean copyGlobalBlocklistToActiveProfile(Context context) {
        File sourceDir = context.getApplicationContext().getDir(DIR, Context.MODE_PRIVATE);
        File targetDir = blocklistDir(context);
        if (sourceDir.equals(targetDir)) {
            return true;
        }
        if (!targetDir.exists() && !targetDir.mkdirs()) {
            ApplicationErrorLog.add(context, "Unable to create active profile DNS blocklist directory");
            return false;
        }
        try {
            copyIfExists(new File(sourceDir, EXACT_FILE), new File(targetDir, EXACT_FILE));
            copyIfExists(new File(sourceDir, SUFFIX_FILE), new File(targetDir, SUFFIX_FILE));
            copyIfExists(new File(sourceDir, EXACT_BACKUP), new File(targetDir, EXACT_BACKUP));
            copyIfExists(new File(sourceDir, SUFFIX_BACKUP), new File(targetDir, SUFFIX_BACKUP));
            copyIfExists(new File(sourceDir, META_FILE), new File(targetDir, META_FILE));
            return true;
        } catch (IOException e) {
            Log.e(TAG, "DNS profile blocklist copy failed", e);
            ApplicationErrorLog.add(context, "DNS profile blocklist copy failed: " + e.getMessage());
            return false;
        }
    }

    static File exactBlockFile(Context context) {
        return new File(blocklistDir(context), EXACT_FILE);
    }

    static File suffixBlockFile(Context context) {
        return new File(blocklistDir(context), SUFFIX_FILE);
    }

    private static void downloadAndParse(String urlString, Result result) {
        HttpURLConnection connection = null;
        try {
            URL url = new URL(urlString);
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(15000);
            connection.setReadTimeout(30000);
            connection.setInstanceFollowRedirects(true);
            int code = connection.getResponseCode();
            if (code < 200 || code >= 300) {
                result.invalid++;
                result.notes.append(urlString).append(": HTTP ").append(code).append('\n');
                return;
            }
            parseStream(connection.getInputStream(), result);
        } catch (IOException e) {
            result.invalid++;
            result.notes.append(urlString).append(": ").append(e.getMessage()).append('\n');
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private static void parseStream(InputStream input, Result result) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
        String line;
        while ((line = reader.readLine()) != null) {
            parseLine(line, result);
        }
    }

    private static void parseLine(String raw, Result result) {
        result.lines++;
        String line = raw == null ? "" : raw.trim();
        if (line.isEmpty() || line.startsWith("#") || line.startsWith("!") || line.startsWith("[")) {
            result.skipped++;
            return;
        }

        if (line.startsWith("@@")) {
            result.skipped++;
            return;
        }

        if (line.startsWith("||")) {
            String domain = normalizeDomain(line.substring(2).replaceFirst("[\\^/$].*$", ""));
            addDomain(result.suffixRules, domain, result);
            return;
        }

        if (line.startsWith("0.0.0.0 ") || line.startsWith("127.0.0.1 ")
                || line.startsWith("::1 ") || line.startsWith(":: ")) {
            String[] parts = line.split("\\s+");
            if (parts.length >= 2) {
                String domain = normalizeDomain(parts[1]);
                addDomain(result.exactRules, domain, result);
                return;
            }
        }

        String[] parts = line.split("\\s+");
        if (parts.length > 1 && isAddressToken(parts[0])) {
            String domain = normalizeDomain(parts[1]);
            addDomain(result.exactRules, domain, result);
            return;
        }

        String candidate = line.split("[#\\s]")[0];
        if (candidate.startsWith("*.") || candidate.startsWith(".")) {
            addDomain(result.suffixRules, normalizeDomain(candidate), result);
        } else {
            addDomain(result.exactRules, normalizeDomain(candidate), result);
        }
    }

    private static void addDomain(Set<String> target, String domain, Result result) {
        if (domain == null || domain.isEmpty() || !DOMAIN_PATTERN.matcher(domain).matches()
                || "localhost".equals(domain)) {
            result.invalid++;
            return;
        }
        if (!target.add(domain)) {
            result.duplicates++;
        }
    }

    private static String normalizeDomain(String raw) {
        if (raw == null) {
            return "";
        }
        String domain = raw.trim().toLowerCase(Locale.US);
        domain = domain.replaceFirst("^https?://", "");
        domain = domain.replaceFirst("/.*$", "");
        domain = domain.replaceFirst("^\\*\\.", "");
        domain = domain.replaceFirst("^\\.", "");
        domain = domain.replaceFirst("\\.$", "");
        return domain;
    }

    private static boolean isAddressToken(String token) {
        return token.matches("^[0-9.]+$") || token.contains(":");
    }

    private static void activate(Context context, Result result) throws IOException {
        if (!result.hasRules()) {
            result.failed = true;
            result.message = "No valid DNS blocklist entries found";
            return;
        }

        File dir = blocklistDir(context);
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("Unable to create DNS blocklist directory");
        }
        File exact = new File(dir, EXACT_FILE);
        File suffix = new File(dir, SUFFIX_FILE);
        copyIfExists(exact, new File(dir, EXACT_BACKUP));
        copyIfExists(suffix, new File(dir, SUFFIX_BACKUP));
        writeRuleFile(new File(dir, EXACT_FILE + ".tmp"), exact, result.exactRules);
        writeRuleFile(new File(dir, SUFFIX_FILE + ".tmp"), suffix, result.suffixRules);
        writeMetadata(context, result.sourceLabel, result.exactRules.size(), result.suffixRules.size(),
                result.duplicates, result.invalid, result.skipped);
        result.message = "Activated DNS blocklist: " + result.exactRules.size()
                + " exact, " + result.suffixRules.size() + " wildcard";
        ApplicationErrorLog.add(context, result.message);
    }

    private static void writeRuleFile(File tmp, File target, Set<String> rules) throws IOException {
        if (tmp.exists() && !tmp.delete()) {
            throw new IOException("Unable to replace temporary " + tmp.getName());
        }
        try (OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(tmp, false), StandardCharsets.UTF_8)) {
            for (String rule : rules) {
                writer.write(rule);
                writer.write('\n');
            }
        }
        if (target.exists() && !target.delete()) {
            throw new IOException("Unable to replace " + target.getName());
        }
        if (!tmp.renameTo(target)) {
            throw new IOException("Unable to activate " + target.getName());
        }
    }

    private static void writeMetadata(Context context, String source, int exact, int suffix,
                                      int duplicates, int invalid, int skipped) throws IOException {
        File meta = new File(blocklistDir(context), META_FILE);
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date());
        try (OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(meta, false), StandardCharsets.UTF_8)) {
            writer.write("updated=");
            writer.write(timestamp);
            writer.write('\n');
            writer.write("source=");
            writer.write(source == null ? "unknown" : source);
            writer.write('\n');
            writer.write("exact=");
            writer.write(String.valueOf(exact));
            writer.write('\n');
            writer.write("wildcard=");
            writer.write(String.valueOf(suffix));
            writer.write('\n');
            writer.write("duplicates=");
            writer.write(String.valueOf(duplicates));
            writer.write('\n');
            writer.write("invalid=");
            writer.write(String.valueOf(invalid));
            writer.write('\n');
            writer.write("skipped=");
            writer.write(String.valueOf(skipped));
            writer.write('\n');
        }
    }

    private static int countLines(File file) throws IOException {
        if (!file.exists()) {
            return 0;
        }
        int count = 0;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
            while (reader.readLine() != null) {
                count++;
            }
        }
        return count;
    }

    private static void copyIfExists(File source, File target) throws IOException {
        if (!source.exists()) {
            return;
        }
        try (FileInputStream input = new FileInputStream(source);
             FileOutputStream output = new FileOutputStream(target, false)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) != -1) {
                output.write(buffer, 0, read);
            }
        }
    }

    private static File blocklistDir(Context context) {
        return context.getApplicationContext()
                .getDir(G.dnsHijackBlocklistDirectoryName(DIR), Context.MODE_PRIVATE);
    }

    public static final class Result {
        private final Set<String> exactRules = new LinkedHashSet<>();
        private final Set<String> suffixRules = new LinkedHashSet<>();
        private final StringBuilder notes = new StringBuilder();
        private final String sourceLabel;
        public int lines;
        public int duplicates;
        public int invalid;
        public int skipped;
        public int sources;
        public boolean failed;
        public String message = "";

        private Result(String sourceLabel) {
            this.sourceLabel = sourceLabel;
        }

        public boolean hasRules() {
            return !exactRules.isEmpty() || !suffixRules.isEmpty();
        }

        public String summary() {
            StringBuilder summary = new StringBuilder();
            summary.append(message);
            summary.append("\nExact: ").append(exactRules.size());
            summary.append("\nWildcard: ").append(suffixRules.size());
            summary.append("\nDuplicates: ").append(duplicates);
            summary.append("\nInvalid: ").append(invalid);
            summary.append("\nSkipped: ").append(skipped);
            if (notes.length() > 0) {
                summary.append("\n\n").append(notes);
            }
            return summary.toString();
        }
    }
}
