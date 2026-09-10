package io.mikko.fastjsoncheck;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 命令行入口。
 *
 * <pre>
 *   java -jar fastjson-check.jar &lt;路径&gt; [更多路径...] [选项]
 * </pre>
 *
 * <p>退出码：0 = 未发现需处理项；1 = 发现 CRITICAL/HIGH（便于 CI 卡门禁）；2 = 用法错误；
 * <b>4 = 有文件读不动</b>（2026-09-10 加）。
 *
 * <p>🔴 <b>4 的含义</b>：0 从此意味着「扫完了<b>且每个文件都真的读进去了</b>」。
 * 在此之前，读不动的文件只在 stdout 留一行提示而退出码照旧是 0 —— 而 CI 与脚本看的是退出码，
 * 于是「我没能读它」在自动化里等于「通过」。留痕是给人看的，退出码是给机器看的，两者缺一不可。
 *
 * <p>🔴 <b>不动现有约定</b>：发现真问题时<b>不降级</b>成 4 —— 1 仍然优先。
 * 4 只在「没发现需处理项，但有文件没能读进去」时出现。
 */
public final class Main {

    // ⚠️ 与 pom 的 <version> 是**两份**，改 pom 时没有任何东西会提醒你同步，而且漂移时零报错。
    //    （spring-eol-check 0.2.0 就这么打印过 0.1.0。）
    //    根治办法是从 MANIFEST 的 Implementation-Version 读 —— 那是下一步，先把两处对齐。
    static final String VERSION = "0.3.0";

    private static final int EXIT_OK = 0;
    private static final int EXIT_FOUND = 1;
    private static final int EXIT_USAGE = 2;
    /** 有文件读不动 —— 「我没能读它」不许在自动化里等于「通过」（2026-09-10 加）。 */
    private static final int EXIT_UNREADABLE = 4;

    /**
     * 全部输出走这里，以便控制字符编码。
     *
     * <p>为什么需要这么做：Windows 上 Java 拿不到控制台的真实代码页，
     * {@code file.encoding} 与 {@code chcp} 常常对不上（例如 Java 认为是 GBK、
     * 控制台实际是 65001/UTF-8），中文就会变成乱码。
     * 默认沿用平台编码（覆盖标准中文 Windows 与 Linux 两种常见情况），
     * 乱码时用 {@code --utf8} 或 {@code --gbk} 手动指定。
     *
     * <p>🔴 <b>package-private（不是 private）</b>：插件模式（{@link ScanMojo}）要把它临时换成
     * UTF-8 缓冲、渲染完再复原。CLI 的 {@code --utf8/--gbk} 开关在插件模式下够不着，
     * 而报告是中文 —— 走 {@code System.out} 在 GBK 平台上必然乱码。
     */
    static PrintStream out = System.out;

    public static void main(String[] args) {
        List<String> targets = new ArrayList<String>();
        boolean json = false;
        boolean color = System.console() != null;
        String encoding = null;

        for (String arg : args) {
            if ("--help".equals(arg) || "-h".equals(arg)) {
                printUsage();
                System.exit(EXIT_OK);
            } else if ("--version".equals(arg) || "-v".equals(arg)) {
                out.println("fastjson-check " + VERSION);
                System.exit(EXIT_OK);
            } else if ("--json".equals(arg)) {
                json = true;
            } else if ("--utf8".equals(arg)) {
                encoding = "UTF-8";
            } else if ("--gbk".equals(arg)) {
                encoding = "GBK";
            } else if ("--no-color".equals(arg)) {
                color = false;
            } else if ("--color".equals(arg)) {
                color = true;
            } else if (arg.startsWith("-")) {
                System.err.println("未知选项：" + arg);
                printUsage();
                System.exit(EXIT_USAGE);
            } else {
                targets.add(arg);
            }
        }

        if (targets.isEmpty()) {
            printUsage();
            System.exit(EXIT_USAGE);
        }

        // JSON 恒用 UTF-8：JSON 标准要求如此，且多为管道/文件消费，与控制台编码无关
        out = createOut(json ? "UTF-8" : encoding);

        JarScanner scanner = new JarScanner();
        for (String t : targets) {
            scanner.scan(new File(t));
        }

        List<Detection> found = new ArrayList<Detection>(scanner.detections());
        // 高危排前面，方便一眼看到最该处理的
        Collections.sort(found, new Comparator<Detection>() {
            public int compare(Detection a, Detection b) {
                return a.severity().ordinal() - b.severity().ordinal();
            }
        });

        if (json) {
            out.println(toJson(targets, scanner, found));
        } else {
            printReport(targets, scanner, found, color);
        }

        for (Detection d : found) {
            if (d.severity().isActionable()) {
                System.exit(EXIT_FOUND);
            }
        }
        // 🔴 顺序不能反：发现真问题时不降级成 4，1 优先（Mikko 拍的「只新增一个码、不动现有约定」）。
        //    走到这里说明没有需处理项 —— 此时「有文件没能读进去」必须让 0 变成 4，
        //    否则报告末尾那句「未发现 fastjson。」在 CI 里就是一句没有依据的「你是安全的」。
        if (scanner.hasUnreadable()) {
            System.exit(EXIT_UNREADABLE);
        }
        System.exit(EXIT_OK);
    }

    // ---------------- 控制台报告 ----------------

    // package-private：插件模式复用同一套渲染，保证 CLI 与插件的报告逐字一致
    // —— 两份渲染代码必然漂移，而漂移时没有任何东西会报错。
    static void printReport(List<String> targets, JarScanner scanner,
                                    List<Detection> found, boolean color) {
        out.println();
        out.println("fastjson-check " + VERSION + "  —— fastjson 应急排查（离线，不外传任何数据）");
        out.println();
        out.println("扫描目标：" + join(targets, "、"));
        out.println("已展开归档：" + scanner.scannedArchives() + " 个");
        out.println();

        if (found.isEmpty()) {
            out.println(paint("未发现 fastjson。", Ansi.GREEN, color));
            out.println();
            out.println("说明：本工具通过查找 com/alibaba/fastjson(2)/JSON.class 判定，");
            out.println("      若依赖被改包名重打包（relocate），可能无法识别。");
            printWarnings(scanner);
            return;
        }

        out.println("发现 " + found.size() + " 处 fastjson：");
        out.println();

        for (Detection d : found) {
            String sev = "[" + d.severity().label() + "]";
            out.println(paint(sev, colorOf(d.severity()), color)
                    + " " + d.artifact + " " + (d.version != null ? d.version : "版本未知"));
            out.println("  位置　　：" + d.location);
            out.println("  版本来源：" + d.versionSource.label());
            if (d.springBootFatJar) {
                out.println("  场景　　：Spring Boot fat-JAR"
                        + paint("  ← CVE-2026-16723 的主要在野利用场景", Ansi.YELLOW, color));
            }
            if (d.shaded) {
                out.println("  " + paint("注意　　：疑似被 shade 进宿主 jar（有 class 但无 Maven 元数据）,"
                        + "mvn dependency:tree 查不到它", Ansi.YELLOW, color));
            }
            out.println("  结论　　：" + d.verdict.reason);
            out.println("  处置　　：" + d.verdict.advice);
            out.println();
        }

        Map<Severity, Integer> counts = new LinkedHashMap<Severity, Integer>();
        for (Severity s : Severity.values()) {
            counts.put(s, 0);
        }
        for (Detection d : found) {
            counts.put(d.severity(), counts.get(d.severity()) + 1);
        }
        StringBuilder summary = new StringBuilder("汇总：");
        for (Map.Entry<Severity, Integer> e : counts.entrySet()) {
            if (e.getValue() > 0) {
                summary.append(e.getKey().label()).append(' ').append(e.getValue()).append("　");
            }
        }
        out.println(summary.toString().trim());
        printWarnings(scanner);
    }

    private static void printWarnings(JarScanner scanner) {
        if (scanner.warnings().isEmpty()) {
            return;
        }
        out.println();
        out.println("扫描过程中的提示：");
        for (String w : scanner.warnings()) {
            out.println("  - " + w);
        }
    }

    // ---------------- JSON 输出 ----------------

    /** 手写 JSON，刻意不引入任何 JSON 库 —— 排查工具不该再往环境里塞依赖。 */
    static String toJson(List<String> targets, JarScanner scanner, List<Detection> found) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"tool\": \"fastjson-check\",\n");
        sb.append("  \"version\": \"").append(esc(VERSION)).append("\",\n");
        sb.append("  \"scannedArchives\": ").append(scanner.scannedArchives()).append(",\n");

        sb.append("  \"targets\": [");
        for (int i = 0; i < targets.size(); i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append('"').append(esc(targets.get(i))).append('"');
        }
        sb.append("],\n");

        sb.append("  \"findings\": [\n");
        for (int i = 0; i < found.size(); i++) {
            Detection d = found.get(i);
            sb.append("    {\n");
            sb.append("      \"severity\": \"").append(esc(d.severity().label())).append("\",\n");
            sb.append("      \"artifact\": \"").append(esc(d.artifact)).append("\",\n");
            sb.append("      \"version\": ").append(d.version == null ? "null" : "\"" + esc(d.version) + "\"").append(",\n");
            sb.append("      \"versionSource\": \"").append(esc(d.versionSource.name())).append("\",\n");
            sb.append("      \"location\": \"").append(esc(d.location)).append("\",\n");
            sb.append("      \"springBootFatJar\": ").append(d.springBootFatJar).append(",\n");
            sb.append("      \"shaded\": ").append(d.shaded).append(",\n");
            sb.append("      \"reason\": \"").append(esc(d.verdict.reason)).append("\",\n");
            sb.append("      \"advice\": \"").append(esc(d.verdict.advice)).append("\"\n");
            sb.append("    }").append(i < found.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ],\n");

        sb.append("  \"warnings\": [\n");
        List<String> ws = scanner.warnings();
        for (int i = 0; i < ws.size(); i++) {
            sb.append("    \"").append(esc(ws.get(i))).append('"')
              .append(i < ws.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ]\n");
        sb.append("}");
        return sb.toString();
    }

    static String esc(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    // ---------------- 杂项 ----------------

    private static void printUsage() {
        out.println();
        out.println("fastjson-check " + VERSION);
        out.println("查出你的 jar 里到底有没有 fastjson、藏在哪、是否受 CVE-2026-16723 影响。");
        out.println();
        out.println("用法：");
        out.println("  java -jar fastjson-check.jar <路径> [更多路径...] [选项]");
        out.println();
        out.println("路径可以是：");
        out.println("  - 一个 jar / war 文件（含 Spring Boot fat-JAR，会自动逐层展开）");
        out.println("  - 一个目录（递归查找其中所有 jar/war）");
        out.println();
        out.println("选项：");
        out.println("  --json        输出 JSON，便于接入流水线（恒为 UTF-8）");
        out.println("  --utf8        强制以 UTF-8 输出（控制台中文乱码时用）");
        out.println("  --gbk         强制以 GBK 输出（控制台中文乱码时用）");
        out.println("  --no-color    关闭彩色输出");
        out.println("  -h, --help    显示本帮助");
        out.println("  -v, --version 显示版本");
        out.println();
        out.println("退出码：0 = 未发现需处理项；1 = 发现 CRITICAL/HIGH；2 = 用法错误；");
        out.println("        4 = 有文件读不动（0 表示「扫完了且每个文件都真的读进去了」）");
        out.println();
        out.println("示例：");
        out.println("  java -jar fastjson-check.jar ./app.jar");
        out.println("  java -jar fastjson-check.jar /opt/apps --json");
        out.println();
        out.println("本工具完全离线运行，不联网、不上传任何数据。");
        out.println();
    }

    /**
     * 按指定编码创建标准输出流。
     *
     * @param encoding 目标编码；传 null 表示沿用平台默认
     */
    private static PrintStream createOut(String encoding) {
        String enc = encoding;
        if (enc == null) {
            enc = System.getProperty("file.encoding");
        }
        if (enc == null) {
            return System.out;
        }
        try {
            return new PrintStream(new FileOutputStream(FileDescriptor.out), true, enc);
        } catch (UnsupportedEncodingException e) {
            // 指定的编码不被 JVM 支持时，退回默认输出，不因为编码问题让工具跑不起来
            return System.out;
        }
    }

    private static String colorOf(Severity s) {
        switch (s) {
            case CRITICAL: return Ansi.RED;
            case HIGH:     return Ansi.YELLOW;
            case MEDIUM:   return Ansi.YELLOW;
            case OK:       return Ansi.GREEN;
            default:       return Ansi.RESET;
        }
    }

    private static String paint(String text, String color, boolean enabled) {
        return enabled ? color + text + Ansi.RESET : text;
    }

    private static String join(List<String> items, String sep) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) {
                sb.append(sep);
            }
            sb.append(items.get(i));
        }
        return sb.toString();
    }

    private Main() {
    }

    /** ANSI 颜色码。 */
    private static final class Ansi {
        static final String RESET = "\u001B[0m";
        static final String RED = "\u001B[31m";
        static final String GREEN = "\u001B[32m";
        static final String YELLOW = "\u001B[33m";
    }
}
