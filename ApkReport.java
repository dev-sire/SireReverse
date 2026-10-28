import java.io.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.regex.*;
import java.util.stream.*;
import java.util.zip.ZipFile;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.*;

/**
 * APK Report - developed by Aman Shahid.
 * Decoding is done by Apktool (iBotPeaches, Apache-2.0), bundled inside this jar.
 * Flow: decode APK -> parse manifest -> scan decompiled code -> one LLM call -> concise report.
 */
public class ApkReport {

    static final String AUTHOR = "Aman Shahid";
    static final String VERSION = "2.0";
    static final int W = 74; // inner width of panels

    static final Set<String> DANGEROUS = Set.of(
        "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CONTACTS", "WRITE_CONTACTS", "READ_CALL_LOG",
        "CALL_PHONE", "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
        "ACCESS_BACKGROUND_LOCATION", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
        "MANAGE_EXTERNAL_STORAGE", "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "SYSTEM_ALERT_WINDOW",
        "REQUEST_INSTALL_PACKAGES", "BIND_ACCESSIBILITY_SERVICE", "READ_CALENDAR", "GET_ACCOUNTS",
        "BODY_SENSORS");

    // ---------- UI state ----------

    static boolean COLOR, UNICODE, ANIM;
    static String OK = "[OK]", CROSS = "[X]", WARN = "[!]", BULLET = "-";
    static final Object LOCK = new Object();
    static final String CYAN = "36", GREEN = "32", YELLOW = "33", RED = "31", DIM = "2",
        BOLD = "1", MAGENTA = "1;35", BCYAN = "1;36";

    public static void main(String[] args) throws Exception {
        String apk = null, outDir = null;
        boolean noAi = false, plain = false, fancy = false, help = false;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-o" -> outDir = args[++i];
                case "--no-ai" -> noAi = true;
                case "--plain" -> plain = true;
                case "--fancy" -> fancy = true;
                case "-h", "--help" -> help = true;
                default -> apk = args[i];
            }
        }
        initUi(plain, fancy);
        banner();
        if (help) { usage(); return; }
        if (apk == null || !Files.isRegularFile(Path.of(apk))) {
            System.err.println(c(RED, CROSS + " Error: APK file not found.") + "\n");
            usage();
            System.exit(2);
        }
        if (outDir == null) {
            String base = Path.of(apk).getFileName().toString().replaceAll("(?i)\\.apk$", "");
            outDir = base + "_decoded";
        }
        long t0 = System.nanoTime();

        // Target fingerprint
        Stats st = new Stats();
        try { apkInfo(Path.of(apk), st); } catch (Exception e) { note("Could not fingerprint APK: " + e.getMessage()); }
        List<String> tl = new ArrayList<>();
        tl.add(kv("File", Path.of(apk).getFileName().toString()));
        tl.add(kv("Size", human(st.apkBytes)));
        if (st.sha256.length() == 64) {
            tl.add(kv("SHA-256", st.sha256.substring(0, 32)));
            tl.add(kv("", st.sha256.substring(32)));
        } else {
            tl.add(kv("SHA-256", st.sha256));
        }
        tl.add(kv("Archive entries", num(st.apkEntries) + "  (" + st.dexFiles + " dex)"));
        tl.add(kv("Output directory", outDir));
        System.out.println();
        box("TARGET", tl);

        // 1. Decode with Apktool (standard procedure, no AI involved here)
        stage(1, 4, "Decoding APK with Apktool");
        Spinner sp = new Spinner("Starting Apktool ...");
        try {
            decode(apk, outDir, sp);
            sp.done("APK decoded");
        } catch (Exception e) {
            String[] m = String.valueOf(e.getMessage()).split("\n", 2);
            sp.fail(m[0]);
            if (m.length > 1) System.err.println(m[1]);
            System.exit(1);
        }

        // 2. Manifest findings
        stage(2, 4, "Analysing AndroidManifest.xml");
        sp = new Spinner("Parsing manifest ...");
        String manifestFacts = analyse(Path.of(outDir));
        sp.done("Manifest parsed");
        box("MANIFEST FINDINGS", manifestLines(manifestFacts));

        // 3. Code & resource metrics
        stage(3, 4, "Scanning decompiled output");
        scanCode(Path.of(outDir), st);
        dashboard(st);
        String facts = manifestFacts + codeFacts(st);

        // 4. LLM report (Gemini preferred, Anthropic optional)
        stage(4, 4, "Generating security report");
        String report;
        String gKey = firstEnv("GEMINI_API_KEY", "GOOGLE_API_KEY");
        String aKey = firstEnv("ANTHROPIC_API_KEY");
        if (noAi || (gKey == null && aKey == null)) {
            System.out.println("  " + c(YELLOW, WARN) + " AI summary skipped ("
                + (noAi ? "--no-ai" : "no GEMINI_API_KEY set") + "). Showing raw findings.");
            report = "# Static findings (no AI summary)\n\n" + facts;
        } else {
            String who = gKey != null ? "Gemini" : env("ANTHROPIC_MODEL", "claude-sonnet-5-5");
            sp = new Spinner("Asking " + who + " to write the report ...");
            try {
                if (gKey != null) {
                    report = askGemini(gKey, facts);
                } else {
                    report = askLlm(aKey, env("ANTHROPIC_MODEL", "claude-sonnet-5-5"), facts);
                }
                sp.done("Report generated");
            } catch (Exception e) {
                sp.fail("LLM call failed: " + String.valueOf(e.getMessage()).split("\n")[0]);
                System.out.println("  " + c(DIM, "Falling back to raw findings."));
                report = "# Static findings (AI summary failed)\n\n" + facts;
            }
        }

        String footer = "\n---\nDecoded by Apktool (iBotPeaches, Apache-2.0). Developed by " + AUTHOR + ".\n";
        System.out.println();
        System.out.println(c(DIM, (UNICODE ? "─" : "-").repeat(W + 2)));
        System.out.println(c(BCYAN, "  SECURITY REPORT"));
        System.out.println(c(DIM, (UNICODE ? "─" : "-").repeat(W + 2)));
        renderReport(report);

        Path out = Path.of(outDir, "REPORT.md");
        Files.writeString(out, report + "\n\n" + insightsMd(st) + footer);

        System.out.println();
        System.out.println(c(DIM, (UNICODE ? "─" : "-").repeat(W + 2)));
        System.out.println("  " + c(GREEN, OK) + " " + c(BOLD, "Analysis complete")
            + c(DIM, " in " + f("%.1fs", (System.nanoTime() - t0) / 1e9)));
        System.out.println("  " + c(DIM, pad("Report saved", 16)) + out.toAbsolutePath());
        System.out.println("  " + c(DIM, pad("Decoded files", 16)) + Path.of(outDir).toAbsolutePath());
        System.out.println();
        System.out.println("  " + c(DIM, "Decoded by Apktool (iBotPeaches, Apache-2.0)  |  Developed by ") + c(BOLD, AUTHOR));
        System.out.println();
    }

    // ---------- terminal UI ----------

    static void initUi(boolean plain, boolean forceFancy) {
        boolean tty = System.console() != null;
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        boolean legacyWin = os.contains("win") && System.getenv("WT_SESSION") == null
            && System.getenv("TERM") == null && System.getenv("ConEmuANSI") == null;
        boolean fancy = forceFancy || (!plain && !legacyWin);
        COLOR = tty && fancy && System.getenv("NO_COLOR") == null;
        UNICODE = fancy;
        ANIM = tty;
        if (UNICODE) {
            System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8));
            System.setErr(new PrintStream(new FileOutputStream(FileDescriptor.err), true, StandardCharsets.UTF_8));
            OK = "✔"; CROSS = "✘"; WARN = "⚠"; BULLET = "•";
        }
    }

    static String c(String code, String s) { return COLOR ? "\u001B[" + code + "m" + s + "\u001B[0m" : s; }

    static String visible(String s) { return s.replaceAll("\u001B\\[[0-9;]*m", ""); }

    static String pad(String s, int w) {
        int v = visible(s).length();
        return v >= w ? s : s + " ".repeat(w - v);
    }

    static String fit(String s, int n) { return s.length() <= n ? s : s.substring(0, Math.max(0, n - 3)) + "..."; }

    static String tail(String s, int n) { return s.length() <= n ? s : (UNICODE ? "…" : "~") + s.substring(s.length() - n + 1); }

    static String f(String fmt, Object... a) { return String.format(Locale.US, fmt, a); }

    static String num(long x) { return f("%,d", x); }

    static String human(long b) {
        if (b < 1024) return b + " B";
        double v = b;
        String[] u = {"KB", "MB", "GB"};
        int i = -1;
        do { v /= 1024; i++; } while (v >= 1024 && i < 2);
        return f("%.1f %s", v, u[i]);
    }

    static String hbar(double frac, int width) {
        int filled = (int) Math.round(frac * width);
        if (frac > 0 && filled == 0) filled = 1;
        filled = Math.min(filled, width);
        return c(CYAN, (UNICODE ? "█" : "#").repeat(filled)) + c(DIM, (UNICODE ? "░" : "-").repeat(width - filled));
    }

    static void clearLine() { System.out.print("\r" + " ".repeat(W + 4) + "\r"); }

    /** Prints a warning without clobbering an active spinner/progress line. */
    static void note(String msg) {
        synchronized (LOCK) {
            if (ANIM) clearLine();
            System.err.println(c(YELLOW, "  " + WARN + " " + msg));
        }
    }

    static void banner() {
        String[] art = {
            "   _____ _           ____",
            "  / ___/(_)_______  / __ \\___ _   _____  _____________",
            "  \\__ \\/ / ___/ _ \\/ /_/ / _ \\ | / / _ \\/ ___/ ___/ _ \\",
            " ___/ / / /  /  __/ _, _/  __/ |/ /  __/ /  (__  )  __/",
            "/____/_/_/   \\___/_/ |_|\\___/|___/\\___/_/  /____/\\___/"
        };
        String[] grad = {"38;5;51", "38;5;45", "38;5;39", "38;5;33", "38;5;27"};
        String rule = c(DIM, (UNICODE ? "─" : "-").repeat(W + 2));
        System.out.println();
        for (int i = 0; i < art.length; i++) System.out.println(c(grad[i], art[i]));
        System.out.println(rule);
        System.out.println("  " + c(BOLD, "Android APK Static Analysis & Decompilation Toolkit") + c(DIM, "   v" + VERSION));
        System.out.println("  " + c(DIM, "Developed by ") + c(BCYAN, AUTHOR));
        System.out.println("  " + c(DIM, "Decoding engine: Apktool (iBotPeaches, Apache-2.0)"));
        System.out.println(rule);
    }

    static void usage() {
        System.out.println();
        System.out.println(c(BOLD, "Usage:") + " java -jar apk-report.jar <app.apk> [-o outdir] [--no-ai] [--plain]\n");
        System.out.println(c(BOLD, "Options:"));
        System.out.println("  -o <dir>     output directory (default: <apk name>_decoded)");
        System.out.println("  --no-ai      skip the AI summary, show raw findings");
        System.out.println("  --plain      ASCII only, no colours (for old Windows consoles / logs)");
        System.out.println("  --fancy      force colours and Unicode even if auto-detection says no\n");
        System.out.println(c(BOLD, "Env:"));
        System.out.println("  GEMINI_API_KEY      enables the AI-written report (Gemini)");
        System.out.println("  GEMINI_MODEL        optional model override (default gemini-3.1-flash-lite,");
        System.out.println("                      falls back to gemini-3-flash-preview)");
        System.out.println("  ANTHROPIC_API_KEY   optional alternative provider");
        System.out.println("  NO_COLOR            disable colours");
    }

    static void stage(int n, int total, String title) {
        System.out.println();
        System.out.println(c(BCYAN, "[" + n + "/" + total + "]") + " " + c(BOLD, title));
    }

    static String kv(String k, String v) { return c(DIM, pad(k, 24)) + v; }

    static String sub(String title) {
        return c(MAGENTA, (UNICODE ? "── " : "-- ") + title + " " + (UNICODE ? "─" : "-").repeat(Math.max(2, W - 2 - 4 - title.length())));
    }

    static void box(String title, List<String> lines) {
        String tl = UNICODE ? "┌" : "+", tr = UNICODE ? "┐" : "+", bl = UNICODE ? "└" : "+", br = UNICODE ? "┘" : "+";
        String h = UNICODE ? "─" : "-", v = UNICODE ? "│" : "|";
        String t = " " + title + " ";
        System.out.println(c(CYAN, tl + h) + c(BCYAN, t) + c(CYAN, h.repeat(Math.max(0, W - 1 - t.length())) + tr));
        for (String line : lines) {
            String s = line;
            if (visible(s).length() > W - 2) s = visible(s).substring(0, W - 3) + (UNICODE ? "…" : ">");
            System.out.println(c(CYAN, v) + " " + pad(s, W - 2) + " " + c(CYAN, v));
        }
        System.out.println(c(CYAN, bl + h.repeat(W) + br));
    }

    /** Animated spinner with live label and elapsed time (static lines when output is not a terminal). */
    static class Spinner {
        final String[] frames = UNICODE
            ? new String[]{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
            : new String[]{"|", "/", "-", "\\"};
        volatile String label;
        volatile boolean running = true;
        final long start = System.nanoTime();
        Thread t;

        Spinner(String label) {
            this.label = label;
            if (ANIM) {
                t = new Thread(this::run);
                t.setDaemon(true);
                t.start();
            } else {
                System.out.println("  ... " + label);
            }
        }

        String elapsed() { return f("%.1fs", (System.nanoTime() - start) / 1e9); }

        void run() {
            int i = 0;
            while (running) {
                synchronized (LOCK) {
                    if (!running) break;
                    String s = "  " + c(CYAN, frames[i++ % frames.length]) + " " + fit(label, 56) + c(DIM, "  " + elapsed());
                    System.out.print("\r" + pad(s, W + 2));
                    System.out.flush();
                }
                try { Thread.sleep(80); } catch (InterruptedException e) { return; }
            }
        }

        void stop() {
            running = false;
            if (t != null) { try { t.join(); } catch (InterruptedException ignored) { } }
        }

        void done(String msg) {
            stop();
            synchronized (LOCK) {
                if (ANIM) clearLine();
                System.out.println("  " + c(GREEN, OK) + " " + msg + c(DIM, "  (" + elapsed() + ")"));
            }
        }

        void fail(String msg) {
            stop();
            synchronized (LOCK) {
                if (ANIM) clearLine();
                System.out.println("  " + c(RED, CROSS) + " " + c(RED, msg));
            }
        }
    }

    /** Single-line progress bar. */
    static class Bar {
        final int total;
        final long start = System.nanoTime();
        long last = 0;

        Bar(int total, String label) {
            this.total = total;
            if (!ANIM) System.out.println("  ... " + label);
        }

        void update(int done, String detail) {
            if (!ANIM) return;
            long now = System.nanoTime();
            if (done < total && now - last < 50_000_000L) return;
            last = now;
            double fr = total == 0 ? 1 : (double) done / total;
            String s = "  " + hbar(fr, 28) + " " + f("%3d%%", (int) (fr * 100))
                + c(DIM, "  " + num(done) + "/" + num(total) + "  " + fit(detail, 20));
            synchronized (LOCK) {
                System.out.print("\r" + pad(s, W + 2));
                System.out.flush();
            }
        }

        double finish(String msg) {
            double secs = (System.nanoTime() - start) / 1e9;
            synchronized (LOCK) {
                if (ANIM) clearLine();
                System.out.println("  " + c(GREEN, OK) + " " + msg + c(DIM, "  (" + f("%.1fs", secs) + ")"));
            }
            return secs;
        }
    }

    // ---------- target info ----------

    static void apkInfo(Path apk, Stats s) throws Exception {
        s.apkBytes = Files.size(apk);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = Files.newInputStream(apk)) {
            byte[] buf = new byte[1 << 16];
            int n;
            while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
        }
        s.sha256 = HexFormat.of().formatHex(md.digest());
        try (ZipFile z = new ZipFile(apk.toFile())) {
            s.apkEntries = z.size();
            z.stream().forEach(e -> { if (e.getName().matches("classes\\d*\\.dex")) s.dexFiles++; });
        }
    }

    // ---------- decode ----------

    static void decode(String apk, String outDir, Spinner sp) throws Exception {
        Path tmp = Files.createTempFile("apktool-", ".jar");
        tmp.toFile().deleteOnExit();
        try (InputStream in = ApkReport.class.getResourceAsStream("/apktool.jar")) {
            if (in == null) throw new IllegalStateException("Bundled apktool.jar missing from this jar.");
            Files.copy(in, tmp, StandardCopyOption.REPLACE_EXISTING);
        }
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        Process p = new ProcessBuilder(java, "-jar", tmp.toString(), "d", "-f", "-o", outDir, apk)
            .redirectErrorStream(true).start();
        StringBuilder log = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                log.append(line).append('\n');
                String t = line.replaceFirst("^[IWE]: ", "").trim();
                if (!t.isEmpty()) sp.label = t; // live status from Apktool
            }
        }
        if (p.waitFor() != 0) {
            throw new IllegalStateException("Apktool failed to decode the APK.\n" + log);
        }
    }

    // ---------- analysis ----------

    static String analyse(Path dir) throws Exception {
        Path manifest = dir.resolve("AndroidManifest.xml");
        if (!Files.exists(manifest)) throw new IllegalStateException("No AndroidManifest.xml in " + dir);

        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); // untrusted input
        Element root = f.newDocumentBuilder().parse(manifest.toFile()).getDocumentElement();

        StringBuilder sb = new StringBuilder();
        sb.append("Package: ").append(root.getAttribute("package")).append('\n');
        sb.append("Version: ").append(orNone(root.getAttribute("android:versionName"))).append('\n');

        NodeList sdk = root.getElementsByTagName("uses-sdk");
        if (sdk.getLength() > 0) {
            Element s = (Element) sdk.item(0);
            sb.append("minSdk: ").append(orNone(s.getAttribute("android:minSdkVersion")))
              .append(", targetSdk: ").append(orNone(s.getAttribute("android:targetSdkVersion"))).append('\n');
        }

        // permissions
        List<String> perms = new ArrayList<>(), dangerous = new ArrayList<>();
        NodeList up = root.getElementsByTagName("uses-permission");
        for (int i = 0; i < up.getLength(); i++) {
            String n = ((Element) up.item(i)).getAttribute("android:name");
            perms.add(n);
            if (DANGEROUS.contains(n.substring(n.lastIndexOf('.') + 1))) dangerous.add(n);
        }
        sb.append("Permissions requested: ").append(perms.size()).append('\n');
        sb.append("Dangerous/sensitive permissions: ").append(dangerous.isEmpty() ? "none" : String.join(", ", dangerous)).append('\n');

        // application flags + components
        NodeList apps = root.getElementsByTagName("application");
        if (apps.getLength() > 0) {
            Element app = (Element) apps.item(0);
            sb.append("debuggable: ").append(flag(app, "android:debuggable", "false")).append('\n');
            sb.append("allowBackup: ").append(flag(app, "android:allowBackup", "true (default)")).append('\n');
            sb.append("usesCleartextTraffic: ").append(flag(app, "android:usesCleartextTraffic", "not set")).append('\n');
            sb.append("networkSecurityConfig: ").append(flag(app, "android:networkSecurityConfig", "not set")).append('\n');

            List<String> exported = new ArrayList<>();
            int total = 0;
            for (String tag : new String[]{"activity", "activity-alias", "service", "receiver", "provider"}) {
                NodeList nl = app.getElementsByTagName(tag);
                for (int i = 0; i < nl.getLength(); i++) {
                    Element c = (Element) nl.item(i);
                    total++;
                    String ex = c.getAttribute("android:exported");
                    boolean hasFilter = c.getElementsByTagName("intent-filter").getLength() > 0;
                    boolean isExported = ex.equals("true") || (ex.isEmpty() && hasFilter);
                    if (isExported) exported.add(tag + " " + c.getAttribute("android:name"));
                }
            }
            sb.append("Components: ").append(total).append(" total, ").append(exported.size()).append(" exported\n");
            exported.stream().limit(15).forEach(e -> sb.append("  - exported ").append(e).append('\n'));
            if (exported.size() > 15) sb.append("  ... and ").append(exported.size() - 15).append(" more\n");
        }
        return sb.toString();
    }

    static String flag(Element e, String attr, String dflt) {
        String v = e.getAttribute(attr);
        return v.isEmpty() ? dflt : v;
    }

    static String orNone(String s) { return s == null || s.isEmpty() ? "unknown" : s; }

    /** Turns the plain-text manifest facts into coloured, wrapped panel lines. */
    static List<String> manifestLines(String facts) {
        Map<String, String> label = Map.of(
            "Dangerous/sensitive permissions", "Dangerous permissions",
            "Permissions requested", "Permissions");
        List<String> out = new ArrayList<>();
        for (String line : facts.split("\n")) {
            if (line.startsWith("  - ")) { out.add(c(YELLOW, "    " + BULLET + " " + line.substring(4))); continue; }
            if (line.startsWith("  ...")) { out.add(c(DIM, "    " + line.trim())); continue; }
            int i = line.indexOf(": ");
            if (i < 0) { out.add(line); continue; }
            String k = line.substring(0, i), v = line.substring(i + 2);
            String col = null;
            if (k.equals("debuggable") && v.equals("true")) col = RED;
            else if (k.equals("usesCleartextTraffic") && v.equals("true")) col = RED;
            else if (k.equals("allowBackup") && v.startsWith("true")) col = YELLOW;
            else if (k.startsWith("Dangerous")) col = v.equals("none") ? GREEN : YELLOW;
            List<String> parts = wrap(v, W - 2 - 24);
            for (int j = 0; j < parts.size(); j++) {
                String val = col == null ? parts.get(j) : c(col, parts.get(j));
                out.add(kv(j == 0 ? label.getOrDefault(k, k) : "", val));
            }
        }
        return out;
    }

    static List<String> wrap(String s, int width) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (String tok : s.split("(?<=, )")) {
            if (cur.length() + tok.length() > width && cur.length() > 0) {
                out.add(cur.toString().stripTrailing());
                cur.setLength(0);
            }
            cur.append(tok);
        }
        if (cur.length() > 0) out.add(cur.toString().stripTrailing());
        if (out.isEmpty()) out.add("");
        return out;
    }

    // ---------- decompiled output metrics ----------

    static class Stats {
        // APK
        long apkBytes; int apkEntries, dexFiles; String sha256 = "unavailable";
        // decompiled output
        int totalFiles, totalDirs; long totalBytes;
        int smaliFiles, smaliDirs; long smaliLines, smaliCodeLines, methods, fields;
        int resFiles, layouts, drawables, xml, images, assets, nativeLibs, other;
        Set<String> abis = new TreeSet<>();
        Map<String, long[]> pkgs = new HashMap<>(); // package -> {lines, classes}
        List<Map.Entry<String, Long>> biggest = new ArrayList<>();
        Set<String> urls = new LinkedHashSet<>();
        double scanSeconds;

        void noteBig(String name, long lines) {
            biggest.add(new AbstractMap.SimpleEntry<>(name, lines));
            biggest.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));
            if (biggest.size() > 3) biggest.remove(3);
        }
    }

    static boolean isImage(String n) {
        return n.endsWith(".png") || n.endsWith(".jpg") || n.endsWith(".jpeg") || n.endsWith(".webp")
            || n.endsWith(".gif") || n.endsWith(".bmp") || n.endsWith(".svg");
    }

    static void scanCode(Path dir, Stats s) throws IOException {
        Spinner sp = new Spinner("Indexing decompiled files ...");
        List<Path> all;
        try (Stream<Path> w = Files.walk(dir)) { all = w.collect(Collectors.toList()); }
        List<Path> files = new ArrayList<>();
        for (Path p : all) { if (Files.isDirectory(p)) s.totalDirs++; else if (Files.isRegularFile(p)) files.add(p); }
        s.totalFiles = files.size();
        s.totalDirs = Math.max(0, s.totalDirs - 1); // don't count the root itself
        sp.done("Indexed " + num(files.size()) + " files");

        Pattern http = Pattern.compile("http://[^\\s\"'\\\\]+");
        Set<String> smaliTops = new HashSet<>();
        Bar bar = new Bar(files.size(), "Scanning " + num(files.size()) + " files ...");
        int done = 0;
        for (Path p : files) {
            String rel = dir.relativize(p).toString().replace('\\', '/');
            String[] parts = rel.split("/");
            String top = parts[0];
            String name = parts[parts.length - 1];
            String lower = name.toLowerCase(Locale.ROOT);
            try { s.totalBytes += Files.size(p); } catch (IOException ignored) { }

            if (top.startsWith("smali") && lower.endsWith(".smali") && parts.length > 1) {
                smaliTops.add(top);
                scanSmali(p, parts, s, http);
            } else if (lower.endsWith(".so")) {
                s.nativeLibs++;
                if (top.equals("lib") && parts.length > 2) s.abis.add(parts[1]);
            } else if (top.equals("assets")) {
                s.assets++;
            } else if (isImage(lower)) {
                s.images++;
            } else if (lower.endsWith(".xml")) {
                s.xml++;
            } else {
                s.other++;
            }
            if (top.equals("res")) {
                s.resFiles++;
                if (parts.length > 1) {
                    String d = parts[1];
                    if (d.startsWith("layout")) s.layouts++;
                    else if (d.startsWith("drawable") || d.startsWith("mipmap")) s.drawables++;
                }
            }
            bar.update(++done, name);
        }
        s.smaliDirs = smaliTops.size();
        s.scanSeconds = bar.finish("Scanned " + num(files.size()) + " files, "
            + num(s.smaliLines) + " lines of smali");
    }

    static void scanSmali(Path p, String[] parts, Stats s, Pattern http) {
        s.smaliFiles++;
        String pkg = parts.length > 2
            ? String.join(".", Arrays.copyOfRange(parts, 1, Math.min(parts.length - 1, 4)))
            : "(default package)";
        long lines = 0;
        try (BufferedReader r = new BufferedReader(new InputStreamReader(Files.newInputStream(p), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                lines++;
                String t = line.strip();
                if (t.isEmpty() || t.charAt(0) == '#') continue;
                s.smaliCodeLines++;
                if (t.startsWith(".method ")) s.methods++;
                else if (t.startsWith(".field ")) s.fields++;
                if (s.urls.size() < 15) {
                    Matcher m = http.matcher(line);
                    while (m.find() && s.urls.size() < 15) {
                        String u = m.group();
                        if (!u.contains("schemas.android.com") && !u.contains("www.w3.org")
                            && !u.contains("xmlpull.org") && !u.contains("localhost")) s.urls.add(u);
                    }
                }
            }
        } catch (IOException e) {
            return; // unreadable file: skip, counts stay consistent for the rest
        }
        s.smaliLines += lines;
        long[] pk = s.pkgs.computeIfAbsent(pkg, k -> new long[2]);
        pk[0] += lines;
        pk[1]++;
        String cls = String.join(".", Arrays.copyOfRange(parts, 1, parts.length)).replaceAll("\\.smali$", "");
        s.noteBig(cls, lines);
    }

    /** Text block fed to the LLM (code-metrics part). */
    static String codeFacts(Stats s) {
        StringBuilder sb = new StringBuilder();
        sb.append("Decompiled output: ").append(num(s.totalFiles)).append(" files, ").append(human(s.totalBytes)).append('\n');
        sb.append("Smali files: ").append(s.smaliFiles).append(" across ").append(s.smaliDirs).append(" dex bundle(s)\n");
        sb.append("Smali lines: ").append(num(s.smaliLines)).append(", methods: ").append(num(s.methods))
          .append(", fields: ").append(num(s.fields)).append('\n');
        sb.append("Native libraries: ").append(s.nativeLibs)
          .append(s.abis.isEmpty() ? "" : " (" + String.join(", ", s.abis) + ")").append('\n');
        sb.append("Cleartext http:// URLs in code: ").append(s.urls.isEmpty() ? "none found" : "").append('\n');
        s.urls.forEach(u -> sb.append("  - ").append(u).append('\n'));
        return sb.toString();
    }

    static void dashboard(Stats s) {
        List<String> L = new ArrayList<>();
        L.add(sub("Overview"));
        L.add(kv("Decompiled files", c(BOLD, num(s.totalFiles)) + " in " + num(s.totalDirs) + " folders"));
        L.add(kv("Output size", c(BOLD, human(s.totalBytes)) + c(DIM, "  (APK: " + human(s.apkBytes) + ")")));
        L.add(kv("DEX bundles", c(BOLD, String.valueOf(s.smaliDirs))));
        L.add(kv("Classes (smali files)", c(BOLD, num(s.smaliFiles))));
        L.add(kv("Lines of smali", c(BOLD, num(s.smaliLines)) + c(DIM, "  (" + num(s.smaliCodeLines) + " code lines)")));
        L.add(kv("Methods / Fields", c(BOLD, num(s.methods)) + " / " + c(BOLD, num(s.fields))));
        L.add(kv("Resource files", c(BOLD, num(s.resFiles))
            + c(DIM, "  (" + num(s.layouts) + " layouts, " + num(s.drawables) + " drawables)")));
        L.add(kv("Native libraries", c(BOLD, num(s.nativeLibs))
            + (s.abis.isEmpty() ? "" : c(DIM, "  (" + String.join(", ", s.abis) + ")"))));
        L.add(kv("Assets", c(BOLD, num(s.assets))));

        L.add("");
        L.add(sub("File breakdown"));
        Object[][] cats = {
            {"Smali classes", s.smaliFiles}, {"XML files", s.xml}, {"Images", s.images},
            {"Native libs", s.nativeLibs}, {"Assets", s.assets}, {"Other", s.other}};
        for (Object[] cat : cats) {
            long n = ((Number) cat[1]).longValue();
            double fr = s.totalFiles == 0 ? 0 : (double) n / s.totalFiles;
            L.add(pad((String) cat[0], 16) + " " + hbar(fr, 24) + " " + f("%5.1f%%", fr * 100) + " " + num(n));
        }

        if (s.smaliLines > 0) {
            L.add("");
            L.add(sub("Top packages by code volume"));
            s.pkgs.entrySet().stream()
                .sorted((a, b) -> Long.compare(b.getValue()[0], a.getValue()[0]))
                .limit(5)
                .forEach(e -> {
                    double fr = (double) e.getValue()[0] / s.smaliLines;
                    L.add(pad(tail(e.getKey(), 30), 31) + hbar(fr, 14) + " " + f("%5.1f%%", fr * 100)
                        + " " + num(e.getValue()[0]) + " lines");
                });
            L.add("");
            L.add(sub("Largest classes"));
            for (Map.Entry<String, Long> e : s.biggest) {
                L.add(pad(tail(e.getKey(), 52), 53) + num(e.getValue()) + " lines");
            }
        }

        L.add("");
        L.add(sub("Network exposure"));
        if (s.urls.isEmpty()) {
            L.add(kv("Cleartext http:// URLs", c(GREEN, "none found")));
        } else {
            L.add(kv("Cleartext http:// URLs", c(YELLOW, s.urls.size() + (s.urls.size() >= 15 ? "+" : "") + " found")));
            s.urls.stream().limit(5).forEach(u -> L.add(c(YELLOW, "  " + BULLET + " " + u)));
            if (s.urls.size() > 5) L.add(c(DIM, "  ... and " + (s.urls.size() - 5) + " more (see REPORT.md)"));
        }
        System.out.println();
        box("DECOMPILATION INSIGHTS", L);
        System.out.println(c(DIM, "  Classes/lines are smali (Dalvik assembly), not Java: line counts run higher than the original source."));
    }

    static String insightsMd(Stats s) {
        StringBuilder sb = new StringBuilder("## Decompilation Insights\n\n| Metric | Value |\n|---|---|\n");
        sb.append("| APK size | ").append(human(s.apkBytes)).append(" |\n");
        sb.append("| APK SHA-256 | `").append(s.sha256).append("` |\n");
        sb.append("| Decompiled files | ").append(num(s.totalFiles)).append(" in ").append(num(s.totalDirs)).append(" folders |\n");
        sb.append("| Output size | ").append(human(s.totalBytes)).append(" |\n");
        sb.append("| DEX bundles | ").append(s.smaliDirs).append(" |\n");
        sb.append("| Classes (smali files) | ").append(num(s.smaliFiles)).append(" |\n");
        sb.append("| Lines of smali | ").append(num(s.smaliLines)).append(" (").append(num(s.smaliCodeLines)).append(" code lines) |\n");
        sb.append("| Methods / Fields | ").append(num(s.methods)).append(" / ").append(num(s.fields)).append(" |\n");
        sb.append("| Resource files | ").append(num(s.resFiles)).append(" (").append(num(s.layouts)).append(" layouts, ")
          .append(num(s.drawables)).append(" drawables) |\n");
        sb.append("| Native libraries | ").append(num(s.nativeLibs))
          .append(s.abis.isEmpty() ? "" : " (" + String.join(", ", s.abis) + ")").append(" |\n");
        sb.append("| Assets | ").append(num(s.assets)).append(" |\n");
        if (!s.pkgs.isEmpty()) {
            sb.append("\n### Top packages by code volume\n\n| Package | Classes | Lines |\n|---|---|---|\n");
            s.pkgs.entrySet().stream()
                .sorted((a, b) -> Long.compare(b.getValue()[0], a.getValue()[0]))
                .limit(5)
                .forEach(e -> sb.append("| ").append(e.getKey()).append(" | ").append(num(e.getValue()[1]))
                    .append(" | ").append(num(e.getValue()[0])).append(" |\n"));
        }
        if (!s.urls.isEmpty()) {
            sb.append("\n### Cleartext http:// URLs\n\n");
            s.urls.forEach(u -> sb.append("- ").append(u).append('\n'));
        }
        return sb.toString();
    }

    /** Light Markdown styling for the terminal. */
    static void renderReport(String md) {
        for (String line : md.split("\n")) {
            String t = line.stripTrailing();
            if (t.startsWith("#")) {
                System.out.println();
                System.out.println(c(BCYAN, (UNICODE ? "▌ " : "> ") + t.replaceFirst("^#+\\s*", "")));
                continue;
            }
            t = t.replaceAll("\\*\\*(.+?)\\*\\*", COLOR ? "\u001B[1m$1\u001B[0m" : "$1");
            if (t.matches("^\\s*[-*] .*")) t = t.replaceFirst("^(\\s*)[-*] ", "$1" + Matcher.quoteReplacement(BULLET) + " ");
            System.out.println("  " + t);
        }
    }

    // ---------- Gemini call (single request, no SDK) ----------

    static final String SYSTEM_PROMPT = "You are a mobile application security analyst. Write a concise report "
        + "(max 250 words) in Markdown with exactly these sections: Summary, Key Risks, Recommendations. "
        + "Base every statement only on the findings provided; do not invent details. "
        + "If the findings are thin, say so plainly.";

    /** Tries the best-fit model first, then falls back if it is rate-limited or unavailable. */
    static String askGemini(String key, String facts) throws Exception {
        String forced = System.getenv("GEMINI_MODEL");
        String[] models = (forced != null && !forced.isBlank())
            ? new String[]{forced}
            : new String[]{"gemini-3.1-flash-lite", "gemini-3-flash-preview"};
        String base = env("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com");
        String body = "{\"systemInstruction\":{\"parts\":[{\"text\":" + q(SYSTEM_PROMPT) + "}]},"
            + "\"contents\":[{\"role\":\"user\",\"parts\":[{\"text\":"
            + q("Static findings from a decoded Android APK:\n\n" + facts) + "}]}],"
            + "\"generationConfig\":{\"maxOutputTokens\":4096}}";

        String lastErr = "no model tried";
        for (String model : models) {
            HttpRequest req = HttpRequest.newBuilder(URI.create(base + "/v1beta/models/" + model + ":generateContent"))
                .timeout(Duration.ofSeconds(90))
                .header("content-type", "application/json")
                .header("x-goog-api-key", key)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
            HttpResponse<String> res = HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString());
            int sc = res.statusCode();
            if (sc / 100 == 2) {
                String text = extractText(res.body());
                if (text != null && !text.isBlank()) return text;
                lastErr = model + ": empty response";
            } else {
                lastErr = model + ": HTTP " + sc + " " + res.body();
                if (sc != 429 && sc != 404 && sc != 503) break; // auth/bad request: fallback won't help
            }
            note("(" + lastErr.split("\n")[0] + ") trying next model ...");
        }
        throw new IOException(lastErr);
    }

    // ---------- Anthropic call (single request, no SDK) ----------

    static String askLlm(String key, String model, String facts) throws Exception {
        String system = SYSTEM_PROMPT;
        String user = "Static findings from a decoded Android APK:\n\n" + facts;

        String body = "{\"model\":" + q(model) + ",\"max_tokens\":700,\"system\":" + q(system)
            + ",\"messages\":[{\"role\":\"user\",\"content\":" + q(user) + "}]}";

        String base = env("ANTHROPIC_BASE_URL", "https://api.anthropic.com");
        HttpRequest req = HttpRequest.newBuilder(URI.create(base + "/v1/messages"))
            .timeout(Duration.ofSeconds(90))
            .header("content-type", "application/json")
            .header("x-api-key", key)
            .header("anthropic-version", "2023-06-01")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();
        HttpResponse<String> res = HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString());
        if (res.statusCode() / 100 != 2) {
            throw new IOException("HTTP " + res.statusCode() + ": " + res.body());
        }
        String text = extractText(res.body());
        if (text == null) throw new IOException("No text in response: " + res.body());
        return text;
    }

    static String firstEnv(String... keys) {
        for (String k : keys) { String v = System.getenv(k); if (v != null && !v.isBlank()) return v; }
        return null;
    }

    static String env(String k, String d) {
        String v = System.getenv(k);
        return v == null || v.isBlank() ? d : v;
    }

    /** JSON string literal. */
    static String q(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> { if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c); }
            }
        }
        return b.append('"').toString();
    }

    /** Pulls the first "text" string value out of the API response without a JSON library. */
    static String extractText(String json) {
        int i = json.indexOf("\"text\":");
        if (i < 0) return null;
        i = json.indexOf('"', i + 7);
        if (i < 0) return null;
        StringBuilder b = new StringBuilder();
        for (i++; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"') return b.toString();
            if (c == '\\') {
                char n = json.charAt(++i);
                switch (n) {
                    case 'n' -> b.append('\n');
                    case 't' -> b.append('\t');
                    case 'r' -> b.append('\r');
                    case 'b' -> b.append('\b');
                    case 'f' -> b.append('\f');
                    case 'u' -> { b.append((char) Integer.parseInt(json.substring(i + 1, i + 5), 16)); i += 4; }
                    default -> b.append(n); // \" \\ \/
                }
            } else b.append(c);
        }
        return null;
    }
}