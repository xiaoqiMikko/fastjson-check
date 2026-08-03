package io.mikko.fastjsoncheck;

/**
 * 一条 fastjson 检出记录。
 *
 * <p>本工具的核心价值不是“告诉你有没有用 fastjson”，而是
 * <b>“它藏在哪里、从哪条路被带进来的”</b> —— fastjson 通常是传递依赖，
 * 很多团队根本不知道自己在用它。
 */
public class Detection {

    /**
     * 检出位置的逻辑路径。
     *
     * <p>嵌套 jar 用 {@code !/} 分隔，与 JDK 的 jar URL 写法一致，例如：
     * {@code app.jar!/BOOT-INF/lib/fastjson-1.2.83.jar}
     * —— 这一行直接告诉用户 fastjson 藏在哪个依赖里。
     */
    public final String location;

    /** 构件名：{@code fastjson}（1.x）或 {@code fastjson2}。 */
    public final String artifact;

    /** 版本号；无法确定时为 null。 */
    public final String version;

    /** 版本来源，用于让用户判断这个版本号可不可信。 */
    public final VersionSource versionSource;

    /**
     * 是否为“被打散重塞”的情况：找到了 fastjson 的 class，
     * 却没有对应的 Maven 元数据，说明它很可能被 shade 进了宿主 jar。
     * 这种情况常规依赖树命令（mvn dependency:tree）查不出来，最容易漏。
     */
    public final boolean shaded;

    /** 所在 jar 是否为 Spring Boot fat-JAR —— CVE-2026-16723 的主要在野利用场景。 */
    public final boolean springBootFatJar;

    /** 风险判定结果。 */
    public final VersionRules.Verdict verdict;

    public Detection(String location, String artifact, String version, VersionSource versionSource,
                     boolean shaded, boolean springBootFatJar, VersionRules.Verdict verdict) {
        this.location = location;
        this.artifact = artifact;
        this.version = version;
        this.versionSource = versionSource;
        this.shaded = shaded;
        this.springBootFatJar = springBootFatJar;
        this.verdict = verdict;
    }

    public Severity severity() {
        return verdict.severity;
    }

    /** 版本号的来源渠道，可信度从高到低。 */
    public enum VersionSource {
        /** 来自 META-INF/maven/.../pom.properties，最可信。 */
        POM_PROPERTIES("pom.properties"),
        /** 来自 jar 文件名，如 fastjson-1.2.83.jar，一般可信。 */
        FILE_NAME("jar 文件名"),
        /** 来自 MANIFEST.MF 的 Implementation-Version。 */
        MANIFEST("MANIFEST.MF"),
        /** 未能确定。 */
        UNKNOWN("未知");

        private final String label;

        VersionSource(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }
}
