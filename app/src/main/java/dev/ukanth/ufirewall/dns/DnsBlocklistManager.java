package dev.ukanth.ufirewall.dns;

import android.content.Context;
import android.net.Uri;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
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
import java.util.Iterator;
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
    private static final int JSON_DETECT_BYTES = 8192;
    private static final int MAX_JSON_BUNDLE_BYTES = 16 * 1024 * 1024;
    private static final int JSON_TARGET_GENERIC = 0;
    private static final int JSON_TARGET_EXACT = 1;
    private static final int JSON_TARGET_SUFFIX = 2;
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
            result.sources = 1;
            parsePossiblyJsonStream(input, result);
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
        result.sources = 1;
        try (InputStream input = new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8))) {
            parsePossiblyJsonStream(input, result);
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
            restoreBackup(exactBackup, new File(dir, EXACT_FILE));
            restoreBackup(suffixBackup, new File(dir, SUFFIX_FILE));
            result.finish();
            writeMetadata(context, "rollback", "rollback", countLines(new File(dir, EXACT_FILE)),
                    countLines(new File(dir, SUFFIX_FILE)), 0, 0, 0, 0, 0,
                    result.durationMs());
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
            parsePossiblyJsonStream(connection.getInputStream(), result);
        } catch (IOException e) {
            result.invalid++;
            result.notes.append(urlString).append(": ").append(e.getMessage()).append('\n');
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private static void parsePossiblyJsonStream(InputStream rawInput, Result result) throws IOException {
        BufferedInputStream input = new BufferedInputStream(rawInput);
        input.mark(JSON_DETECT_BYTES);
        int first = firstNonWhitespace(input);
        input.reset();
        if (first == '{' || first == '[') {
            parseJsonBundle(readLimitedString(input), result);
        } else {
            parseStream(input, result);
        }
    }

    private static int firstNonWhitespace(InputStream input) throws IOException {
        for (int i = 0; i < JSON_DETECT_BYTES; i++) {
            int value = input.read();
            if (value == -1) {
                return -1;
            }
            if (!Character.isWhitespace((char) value)) {
                return value;
            }
        }
        return -1;
    }

    private static String readLimitedString(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int total = 0;
        int read;
        while ((read = input.read(buffer)) != -1) {
            total += read;
            if (total > MAX_JSON_BUNDLE_BYTES) {
                throw new IOException("JSON DNS blocklist bundle is too large to import safely");
            }
            output.write(buffer, 0, read);
        }
        return output.toString(StandardCharsets.UTF_8.name());
    }

    private static void parseJsonBundle(String rawJson, Result result) throws IOException {
        String json = rawJson == null ? "" : rawJson.trim();
        if (json.isEmpty()) {
            return;
        }
        result.sourceLabel = result.sourceLabel + " JSON bundle";
        result.notes.append("Detected JSON DNS blocklist bundle\n");
        try {
            if (json.startsWith("[")) {
                parseJsonArray(new JSONArray(json), result, JSON_TARGET_GENERIC);
            } else {
                parseJsonObject(new JSONObject(json), result);
            }
        } catch (JSONException e) {
            throw new IOException("Invalid JSON DNS blocklist bundle: " + e.getMessage(), e);
        }
    }

    private static void parseJsonObject(JSONObject object, Result result) throws JSONException {
        boolean handled = false;
        Iterator<String> keys = object.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            Object value = object.opt(key);
            if (JSONObject.NULL.equals(value)) {
                continue;
            }
            if (isJsonAllowKey(key)) {
                result.skipped += countJsonEntries(value);
                continue;
            }
            int target = classifyJsonRuleKey(key);
            if (target == JSON_TARGET_EXACT || target == JSON_TARGET_SUFFIX) {
                parseJsonValue(value, result, target);
                handled = true;
            } else if (isJsonGenericRuleKey(key)) {
                parseJsonValue(value, result, JSON_TARGET_GENERIC);
                handled = true;
            } else if (isJsonWrapperKey(key) && (value instanceof JSONObject || value instanceof JSONArray)) {
                parseJsonValue(value, result, JSON_TARGET_GENERIC);
                handled = true;
            }
        }

        if (!handled) {
            parseJsonRuleObject(object, result, JSON_TARGET_GENERIC);
        }
    }

    private static void parseJsonArray(JSONArray array, Result result, int target) throws JSONException {
        for (int i = 0; i < array.length(); i++) {
            parseJsonValue(array.opt(i), result, target);
        }
    }

    private static void parseJsonValue(Object value, Result result, int target) throws JSONException {
        if (value == null || JSONObject.NULL.equals(value)) {
            return;
        }
        if (value instanceof JSONArray) {
            parseJsonArray((JSONArray) value, result, target);
        } else if (value instanceof JSONObject) {
            JSONObject object = (JSONObject) value;
            if (!parseJsonRuleObject(object, result, target)) {
                parseJsonObject(object, result);
            }
        } else {
            parseJsonScalar(String.valueOf(value), result, target);
        }
    }

    private static boolean parseJsonRuleObject(JSONObject object, Result result, int parentTarget) throws JSONException {
        String domain = firstJsonString(object, "domain", "host", "hostname", "pattern", "value");
        if (domain.isEmpty()) {
            return false;
        }
        String action = firstJsonString(object, "action", "policy", "decision", "list");
        if (isAllowToken(action)) {
            result.skipped++;
            return true;
        }
        String type = firstJsonString(object, "type", "kind", "rule", "rule_type", "match");
        if (containsToken(type, "regex")) {
            result.skipped++;
            return true;
        }
        int target = parentTarget == JSON_TARGET_EXACT || parentTarget == JSON_TARGET_SUFFIX
                ? parentTarget : JSON_TARGET_GENERIC;
        if (containsToken(type, "suffix") || containsToken(type, "wildcard")
                || containsToken(type, "subdomain")) {
            target = JSON_TARGET_SUFFIX;
        }
        parseJsonScalar(domain, result, target);
        return true;
    }

    private static void parseJsonScalar(String raw, Result result, int target) {
        String value = raw == null ? "" : raw.trim();
        if (value.isEmpty()) {
            result.skipped++;
            return;
        }
        if (target == JSON_TARGET_SUFFIX) {
            result.lines++;
            addDomain(result.suffixRules, normalizeDomain(value), result);
        } else if (target == JSON_TARGET_EXACT) {
            result.lines++;
            addDomain(result.exactRules, normalizeDomain(value), result);
        } else {
            parseLine(value, result);
        }
    }

    private static String firstJsonString(JSONObject object, String... keys) {
        for (String key : keys) {
            String value = object.optString(key, "");
            if (!value.trim().isEmpty()) {
                return value.trim();
            }
        }
        return "";
    }

    private static int classifyJsonRuleKey(String rawKey) {
        String key = normalizeJsonKey(rawKey);
        if (key.contains("suffix") || key.contains("wildcard")) {
            return JSON_TARGET_SUFFIX;
        }
        if (key.equals("exact") || key.equals("exactblock") || key.equals("blockexact")
                || key.equals("host") || key.equals("hosts")) {
            return JSON_TARGET_EXACT;
        }
        return JSON_TARGET_GENERIC;
    }

    private static boolean isJsonGenericRuleKey(String rawKey) {
        String key = normalizeJsonKey(rawKey);
        return key.equals("domain") || key.equals("domains")
                || key.equals("rule") || key.equals("rules")
                || key.equals("entry") || key.equals("entries")
                || key.equals("item") || key.equals("items")
                || key.equals("block") || key.equals("blocked")
                || key.equals("deny") || key.equals("denied")
                || key.equals("blacklist") || key.equals("denylist")
                || key.equals("blocklist") || key.equals("blocklists")
                || (key.contains("domain") && (key.contains("block")
                || key.contains("deny") || key.contains("disallow")));
    }

    private static boolean isJsonWrapperKey(String rawKey) {
        String key = normalizeJsonKey(rawKey);
        return key.equals("data") || key.equals("backup") || key.equals("export")
                || key.equals("dnsblocklist") || key.equals("dnsblocklists")
                || key.equals("blocklist") || key.equals("blocklists");
    }

    private static boolean isJsonAllowKey(String rawKey) {
        String key = normalizeJsonKey(rawKey);
        return isAllowToken(key);
    }

    private static String normalizeJsonKey(String rawKey) {
        return rawKey == null ? "" : rawKey.toLowerCase(Locale.US).replaceAll("[^a-z0-9]", "");
    }

    private static boolean containsToken(String value, String token) {
        return value != null && value.toLowerCase(Locale.US).contains(token);
    }

    private static boolean isAllowToken(String value) {
        if (value == null) {
            return false;
        }
        String token = value.toLowerCase(Locale.US);
        if (token.contains("disallow") || token.contains("deny") || token.contains("block")) {
            return false;
        }
        return token.contains("allow") || token.contains("white");
    }

    private static int countJsonEntries(Object value) {
        if (value instanceof JSONArray) {
            return ((JSONArray) value).length();
        }
        return value == null || JSONObject.NULL.equals(value) ? 0 : 1;
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

        if (line.startsWith("@@") || isUnsupportedAdblockRule(line)) {
            result.skipped++;
            return;
        }

        if (line.startsWith("||")) {
            String domain = normalizeDomain(line.substring(2).replaceFirst("[\\^/$].*$", ""));
            addDomain(result.suffixRules, domain, result);
            return;
        }

        if (parseDnsmasqAddressRule(line, result)) {
            return;
        }

        if (parseUnboundLocalZoneRule(line, result)) {
            return;
        }

        if (line.startsWith("0.0.0.0 ") || line.startsWith("127.0.0.1 ")
                || line.startsWith("::1 ") || line.startsWith(":: ")) {
            parseHostsDomains(line.split("\\s+"), 1, result);
            return;
        }

        String[] parts = line.split("\\s+");
        if (parts.length > 1 && isAddressToken(parts[0])) {
            parseHostsDomains(parts, 1, result);
            return;
        }

        String candidate = line.split("[#\\s]")[0];
        candidate = stripAdblockAnchors(candidate);
        if (candidate.startsWith("*.") || candidate.startsWith(".")) {
            addDomain(result.suffixRules, normalizeDomain(candidate), result);
        } else {
            addDomain(result.exactRules, normalizeDomain(candidate), result);
        }
    }

    private static void parseHostsDomains(String[] parts, int start, Result result) {
        boolean parsed = false;
        for (int i = start; i < parts.length; i++) {
            String token = parts[i] == null ? "" : parts[i].trim();
            if (token.isEmpty() || token.startsWith("#")) {
                break;
            }
            if (isAddressToken(token)) {
                continue;
            }
            addDomain(result.exactRules, normalizeDomain(token), result);
            parsed = true;
        }
        if (!parsed) {
            result.skipped++;
        }
    }

    private static boolean parseDnsmasqAddressRule(String line, Result result) {
        String prefix = "address=/";
        int end;
        if (!line.startsWith(prefix)) {
            return false;
        }
        end = line.indexOf('/', prefix.length());
        if (end <= prefix.length()) {
            result.invalid++;
            return true;
        }
        addDomain(result.suffixRules, normalizeDomain(line.substring(prefix.length(), end)), result);
        return true;
    }

    private static boolean parseUnboundLocalZoneRule(String line, Result result) {
        String lower = line.toLowerCase(Locale.US);
        String value;
        int firstQuote;
        int secondQuote;
        if (!lower.startsWith("local-zone:")) {
            return false;
        }
        if (!(lower.contains("always_null") || lower.contains("always_nxdomain")
                || lower.contains("redirect") || lower.contains("static"))) {
            result.skipped++;
            return true;
        }
        firstQuote = line.indexOf('"');
        secondQuote = firstQuote >= 0 ? line.indexOf('"', firstQuote + 1) : -1;
        if (firstQuote >= 0 && secondQuote > firstQuote) {
            value = line.substring(firstQuote + 1, secondQuote);
        } else {
            String[] parts = line.substring("local-zone:".length()).trim().split("\\s+");
            value = parts.length == 0 ? "" : parts[0];
        }
        addDomain(result.suffixRules, normalizeDomain(value), result);
        return true;
    }

    private static boolean isUnsupportedAdblockRule(String line) {
        return line.startsWith("/") || line.contains("##") || line.contains("#@#")
                || line.contains("#?#") || line.contains("#$#")
                || line.contains("$scriptlet") || line.contains("$removeparam");
    }

    private static String stripAdblockAnchors(String candidate) {
        String value = candidate == null ? "" : candidate.trim();
        value = value.replaceFirst("^\\|+", "");
        value = value.replaceFirst("[\\^|].*$", "");
        return value;
    }

    private static void addDomain(Set<String> target, String domain, Result result) {
        if (domain == null || domain.isEmpty() || "localhost".equals(domain)) {
            result.skipped++;
            return;
        }
        if (!DOMAIN_PATTERN.matcher(domain).matches()) {
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
        File exactBackup = new File(dir, EXACT_BACKUP);
        File suffixBackup = new File(dir, SUFFIX_BACKUP);
        File exactTmp = new File(dir, EXACT_FILE + ".tmp");
        File suffixTmp = new File(dir, SUFFIX_FILE + ".tmp");
        writeTempRuleFile(exactTmp, result.exactRules);
        writeTempRuleFile(suffixTmp, result.suffixRules);
        backupCurrent(exact, exactBackup);
        backupCurrent(suffix, suffixBackup);
        try {
            replaceFromTemp(exactTmp, exact);
            replaceFromTemp(suffixTmp, suffix);
        } catch (IOException e) {
            boolean restored = true;
            try {
                restoreBackup(exactBackup, exact);
                restoreBackup(suffixBackup, suffix);
            } catch (IOException restoreError) {
                restored = false;
                e.addSuppressed(restoreError);
            }
            throw new IOException("DNS blocklist activation failed; previous blocklist "
                    + (restored ? "restored" : "restore failed") + ": " + e.getMessage(), e);
        } finally {
            deleteIfExists(exactTmp);
            deleteIfExists(suffixTmp);
        }
        result.finish();
        writeMetadata(context, result.sourceLabel, "active", result.exactRules.size(), result.suffixRules.size(),
                result.duplicates, result.invalid, result.skipped, result.sources, result.lines,
                result.durationMs());
        result.message = "Activated DNS blocklist: " + result.exactRules.size()
                + " exact, " + result.suffixRules.size() + " wildcard";
        ApplicationErrorLog.add(context, result.message + " in " + formatDuration(result.durationMs()));
    }

    private static void writeTempRuleFile(File tmp, Set<String> rules) throws IOException {
        if (tmp.exists() && !tmp.delete()) {
            throw new IOException("Unable to replace temporary " + tmp.getName());
        }
        try (OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(tmp, false), StandardCharsets.UTF_8)) {
            for (String rule : rules) {
                writer.write(rule);
                writer.write('\n');
            }
        }
    }

    private static void replaceFromTemp(File tmp, File target) throws IOException {
        if (target.exists() && !target.delete()) {
            throw new IOException("Unable to replace " + target.getName());
        }
        if (!tmp.renameTo(target)) {
            throw new IOException("Unable to activate " + target.getName());
        }
    }

    private static void backupCurrent(File source, File backup) throws IOException {
        if (source.exists()) {
            copyIfExists(source, backup);
        } else {
            deleteIfExists(backup);
        }
    }

    private static void restoreBackup(File backup, File target) throws IOException {
        if (backup.exists()) {
            copyIfExists(backup, target);
        } else {
            deleteIfExists(target);
        }
    }

    private static void writeMetadata(Context context, String source, String status, int exact, int suffix,
                                      int duplicates, int invalid, int skipped, int sources,
                                      int lines, long durationMs) throws IOException {
        File meta = new File(blocklistDir(context), META_FILE);
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date());
        try (OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(meta, false), StandardCharsets.UTF_8)) {
            writer.write("updated=");
            writer.write(timestamp);
            writer.write('\n');
            writer.write("status=");
            writer.write(status == null ? "unknown" : status);
            writer.write('\n');
            writer.write("source=");
            writer.write(source == null ? "unknown" : source);
            writer.write('\n');
            writer.write("sources=");
            writer.write(String.valueOf(sources));
            writer.write('\n');
            writer.write("lines=");
            writer.write(String.valueOf(lines));
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
            writer.write("duration_ms=");
            writer.write(String.valueOf(durationMs));
            writer.write('\n');
        }
    }

    private static String formatDuration(long durationMs) {
        if (durationMs < 1000L) {
            return durationMs + "ms";
        }
        return String.format(Locale.US, "%.1fs", durationMs / 1000.0d);
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

    private static void deleteIfExists(File file) throws IOException {
        if (file.exists() && !file.delete()) {
            throw new IOException("Unable to delete " + file.getName());
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
        private final long startedAtMs = System.currentTimeMillis();
        private long finishedAtMs;
        private String sourceLabel;
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

        private void finish() {
            if (finishedAtMs == 0L) {
                finishedAtMs = System.currentTimeMillis();
            }
        }

        private long durationMs() {
            long end = finishedAtMs == 0L ? System.currentTimeMillis() : finishedAtMs;
            return Math.max(0L, end - startedAtMs);
        }

        public boolean hasRules() {
            return !exactRules.isEmpty() || !suffixRules.isEmpty();
        }

        public String summary() {
            StringBuilder summary = new StringBuilder();
            summary.append(message);
            summary.append("\nStatus: ").append(failed ? "failed" : "complete");
            summary.append("\nSources: ").append(sources);
            summary.append("\nLines: ").append(lines);
            summary.append("\nExact: ").append(exactRules.size());
            summary.append("\nWildcard: ").append(suffixRules.size());
            summary.append("\nDuplicates: ").append(duplicates);
            summary.append("\nInvalid: ").append(invalid);
            summary.append("\nSkipped: ").append(skipped);
            summary.append("\nDuration: ").append(formatDuration(durationMs()));
            if (notes.length() > 0) {
                summary.append("\n\n").append(notes);
            }
            return summary.toString();
        }
    }
}
