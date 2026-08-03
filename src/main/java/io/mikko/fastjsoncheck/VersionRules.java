package io.mikko.fastjsoncheck;

/**
 * fastjson 版本风险判定规则 —— 本工具的核心业务逻辑。
 *
 * <p>判定依据（截至 2026-08-04，全部为公开可核验信息）：
 *
 * <p><b>⚠️ 重要更正：官方补丁 1.2.84 已于 2026-07-29 发布。</b>
 * 早期安全通告（含多家英文安全媒体）称“1.x 已 EOL、无官方补丁、只能迁移到 fastjson2”，
 * 该说法在 2026-07-29 之后已不成立。核验依据：
 * <ul>
 *   <li>Maven 中央仓库 {@code com.alibaba:fastjson:1.2.84} 存在，jar 上传时间 2026-07-29。</li>
 *   <li>GitHub {@code alibaba/fastjson} release {@code 1.2.84}，发布于 2026-07-29T08:24:51Z。</li>
 *   <li>关键提交 {@code fix: strengthen autoType type name validation and whitelist verification}
 *       （2026-07-29T07:02:55Z），正对应本 CVE 的类型解析与白名单校验缺陷。</li>
 *   <li>1.2.83 发布于 2022-05，此后 1.x 分支四年无提交 —— 1.2.84 是为本漏洞专门破例发布。</li>
 * </ul>
 * 注意官方为<b>静默发布</b>：1.2.83 的 release 标题标注了“（安全修复）”，
 * 而 1.2.84 仅写“1.2.84版本发布”，未提及安全，这是外界普遍未察觉补丁存在的原因。
 *
 * <p><b>fastjson 1.x（com.alibaba:fastjson）</b>
 * <ul>
 *   <li>1.2.84 及以上：<b>已修复 CVE-2026-16723</b>，是 1.x 用户成本最低的处置路径
 *       （同分支小版本升级，通常无需改代码）。</li>
 *   <li>1.2.68 ~ 1.2.83：CVE-2026-16723，CVSS 9.0 远程代码执行。
 *       <b>默认配置即可利用</b>，无需开启 AutoType、无需 classpath gadget、无需认证。
 *       官方公告 2026-07-21，数日内即出现在野利用，主要针对 Spring Boot fat-JAR 部署。</li>
 *   <li>低于 1.2.68：不受 CVE-2026-16723 影响，但存在历史 AutoType 反序列化 RCE 系列漏洞
 *       （1.2.24 / 1.2.47 / 1.2.62 / 1.2.66 等）。</li>
 * </ul>
 *
 * <p><b>fastjson 2.x（com.alibaba:fastjson2，及 com.alibaba:fastjson 的 2.0.x 兼容包）</b>
 * <ul>
 *   <li>小于等于 2.0.62：存在 autoType 加固缺陷导致的多态反序列化 RCE（seeAlso 路径），
 *       默认配置即可触发。</li>
 *   <li>2.0.63 及以上：已修复，为当前推荐版本。</li>
 * </ul>
 *
 * <p><b>注意</b>：官方推荐的迁移目标 fastjson2 自身在 ≤2.0.62 时也有 RCE，
 * 因此“已迁到 fastjson2”并不等于安全，必须同时看版本。
 */
public final class VersionRules {

    /** fastjson 1.x 受 CVE-2026-16723 影响的下界（含）。 */
    private static final String CVE_2026_16723_LOWER = "1.2.68";
    /** fastjson 1.x 受 CVE-2026-16723 影响的上界（含）。1.2.84 起已修复。 */
    private static final String CVE_2026_16723_UPPER = "1.2.83";
    /** fastjson 1.x 修复 CVE-2026-16723 的首个版本，2026-07-29 发布。 */
    private static final String FASTJSON1_FIXED = "1.2.84";
    /** fastjson2 的首个安全版本。 */
    private static final String FASTJSON2_FIXED = "2.0.63";

    private VersionRules() {
    }

    /**
     * 依据版本号判定风险。
     *
     * @param version 版本字符串，允许带后缀（如 {@code 1.2.83_noneautotype}、{@code 1.2.83.sec01}）
     * @return 判定结果；版本无法解析时返回 {@link Severity#UNKNOWN}
     */
    public static Verdict judge(String version) {
        if (version == null || version.trim().isEmpty()) {
            return new Verdict(Severity.UNKNOWN,
                    "无法确定 fastjson 版本",
                    "请手动确认该 jar 内 fastjson 的版本，再对照 CVE-2026-16723 影响范围判断："
                            + "1.2.68~1.2.83 受影响，1.2.84（2026-07-29 官方修复版）起已修复。");
        }

        int[] parsed = parse(version);
        if (parsed == null) {
            return new Verdict(Severity.UNKNOWN,
                    "版本号 \"" + version + "\" 无法解析",
                    "请手动确认版本并对照 CVE-2026-16723 影响范围判断："
                            + "1.2.68~1.2.83 受影响，1.2.84（2026-07-29 官方修复版）起已修复。");
        }

        int major = parsed[0];

        // ---- fastjson 1.x ----
        if (major == 1) {
            // 1.2.84（2026-07-29）是官方针对本 CVE 的修复版，优先于区间判定。
            if (compare(version, FASTJSON1_FIXED) >= 0) {
                return new Verdict(Severity.OK,
                        "fastjson " + version + " 已包含 CVE-2026-16723 的官方修复（1.2.84 起）",
                        "无需紧急处置。长期仍建议迁移至 fastjson2 " + FASTJSON2_FIXED
                                + " 或更高版本 —— 1.x 属于低维护状态，1.2.84 是为本次漏洞破例发布的，"
                                + "不代表 1.x 恢复常规维护。");
            }

            boolean inCveRange = compare(version, CVE_2026_16723_LOWER) >= 0
                    && compare(version, CVE_2026_16723_UPPER) <= 0;
            if (inCveRange) {
                return new Verdict(Severity.CRITICAL,
                        "命中 CVE-2026-16723（CVSS 9.0 远程代码执行），默认配置即可利用",
                        "处置按成本从低到高："
                                + "①（推荐，改动最小）升级至 fastjson " + FASTJSON1_FIXED
                                + " —— 这是官方 2026-07-29 发布的修复版，同分支小版本升级，通常无需改代码。"
                                + "注意它是静默发布、release 未标注安全修复，因此多数安全通告仍称“无补丁”，实为过时信息；"
                                + "② 长期方案：迁移至 fastjson2 " + FASTJSON2_FIXED + " 或更高版本；"
                                + "③ 上述两条都无法立即执行时，先启用 SafeMode 彻底关闭 AutoType 以缓解，但这不是长期方案。");
            }

            return new Verdict(Severity.HIGH,
                    "fastjson " + version + " 低于 1.2.68，不受 CVE-2026-16723 影响，但存在历史 AutoType 反序列化 RCE",
                    "不受本次 CVE 影响，但 1.2.24 / 1.2.47 / 1.2.62 / 1.2.66 等历史 AutoType 绕过链适用于该版本。"
                            + "建议升级至 fastjson " + FASTJSON1_FIXED + "，或迁移至 fastjson2 "
                            + FASTJSON2_FIXED + " 或更高版本。");
        }

        // ---- fastjson 2.x ----
        if (major == 2) {
            if (compare(version, FASTJSON2_FIXED) < 0) {
                return new Verdict(Severity.CRITICAL,
                        "fastjson2 ≤ 2.0.62 存在多态反序列化 RCE（seeAlso 路径），默认配置即可触发",
                        "升级至 fastjson2 " + FASTJSON2_FIXED + " 或更高版本。"
                                + "注意：从 1.x 迁到 fastjson2 若停留在 ≤2.0.62，同样处于高危状态。");
            }
            return new Verdict(Severity.OK,
                    "fastjson2 " + version + " 高于已知受影响版本",
                    "无需处置。建议保持关注官方安全公告。");
        }

        return new Verdict(Severity.UNKNOWN,
                "无法识别的 fastjson 主版本：" + version,
                "请手动核对该版本的安全状态。");
    }

    /**
     * 比较两个版本号大小，仅比较数值段，忽略 {@code _noneautotype}、{@code .sec01} 等后缀。
     *
     * @return 负数表示 a &lt; b，0 表示相等，正数表示 a &gt; b
     */
    static int compare(String a, String b) {
        int[] va = parse(a);
        int[] vb = parse(b);
        if (va == null || vb == null) {
            return 0;
        }
        for (int i = 0; i < Math.max(va.length, vb.length); i++) {
            int x = i < va.length ? va[i] : 0;
            int y = i < vb.length ? vb[i] : 0;
            if (x != y) {
                return x < y ? -1 : 1;
            }
        }
        return 0;
    }

    /**
     * 从版本字符串中提取数值段。
     *
     * <p>例：{@code 1.2.83_noneautotype} → {@code [1,2,83]}；{@code 2.0.62} → {@code [2,0,62]}。
     * 遇到第一个非数字、非点号的字符即停止，避免把 {@code sec01} 的 01 误当作版本段。
     *
     * @return 数值段数组；无法解析时返回 null
     */
    static int[] parse(String version) {
        if (version == null) {
            return null;
        }
        String v = version.trim();
        // 去掉常见前缀
        if (v.startsWith("v") || v.startsWith("V")) {
            v = v.substring(1);
        }
        StringBuilder numeric = new StringBuilder();
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (Character.isDigit(c) || c == '.') {
                numeric.append(c);
            } else {
                break;
            }
        }
        String[] parts = numeric.toString().split("\\.");
        java.util.List<Integer> nums = new java.util.ArrayList<Integer>();
        for (String p : parts) {
            if (p.isEmpty()) {
                continue;
            }
            try {
                nums.add(Integer.parseInt(p));
            } catch (NumberFormatException e) {
                break;
            }
        }
        if (nums.isEmpty()) {
            return null;
        }
        int[] result = new int[nums.size()];
        for (int i = 0; i < nums.size(); i++) {
            result[i] = nums.get(i);
        }
        return result;
    }

    /** 一次风险判定的结果。 */
    public static final class Verdict {
        public final Severity severity;
        /** 判定结论，一句话说清“为什么是这个等级”。 */
        public final String reason;
        /** 处置建议，告诉用户下一步该做什么。 */
        public final String advice;

        public Verdict(Severity severity, String reason, String advice) {
            this.severity = severity;
            this.reason = reason;
            this.advice = advice;
        }
    }
}
