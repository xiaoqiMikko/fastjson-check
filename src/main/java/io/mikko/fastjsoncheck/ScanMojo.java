package io.mikko.fastjsoncheck;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;

/**
 * Maven 插件入口:{@code mvn io.github.xiaoqimikko:fastjson-check:check}
 *
 * <p><b>为什么插件形态不只是「更方便」</b>:CLI 扫 {@code pom.xml} 时读到的是<b>文本</b> ——
 * 版本可能写成 {@code ${fastjson.version}}、可能继承自 {@code <parent>},
 * 更常见的是<b>根本没写在 pom 里</b>(传递依赖带进来的)。
 * 插件拿到的是 Maven <b>解析完成后</b>的依赖集合,每个依赖都带着本地仓库里的真实 jar 路径,
 * 于是走的正是本工具最擅长的那条路:<b>扫真 jar 里的 {@code com/alibaba/fastjson(2)/JSON.class}</b>,
 * 而不是相信 pom 上写了什么。
 *
 * <p>⚠️ <b>识别边界没有因此改变</b>:判定键仍是那个 class 路径,
 * 所以<b>被 relocate/改包名重打包的依赖依然识别不出来</b>(README「它不是什么」里那条限制照旧)。
 * 插件解决的是「版本写在哪」,不是「包名被改了」。
 *
 * <p>🔴 <b>默认不让构建失败</b>({@link #failOnFound} 默认 false)。
 * 理由与 CLI 的退出码语义<b>刻意不同</b>:命令行是人主动敲的,退出码 1 正是他要的;
 * 而插件会挂在别人的流水线上,一个自查工具不该在用户毫无准备时把构建打红。
 * 要当 CI 门禁请显式开 {@code -Dfastjson-check.failOnFound=true}。
 */
@Mojo(name = "check",
      defaultPhase = LifecyclePhase.VERIFY,
      requiresDependencyResolution = ResolutionScope.TEST,
      threadSafe = true)
public class ScanMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    /**
     * 不扫依赖树,改扫这个路径(目录 / jar / war / Spring Boot fat-jar)。
     * 不设时扫 Maven 解析后的依赖 —— 那是默认且推荐的用法。
     */
    @Parameter(property = "fastjson-check.path")
    private File path;

    /**
     * 发现 CRITICAL / HIGH 时是否让构建失败。
     * <b>默认 false</b>,理由见类注释。
     */
    @Parameter(property = "fastjson-check.failOnFound", defaultValue = "false")
    private boolean failOnFound;

    /** 跳过执行。 */
    @Parameter(property = "fastjson-check.skip", defaultValue = "false")
    private boolean skip;

    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            getLog().info("fastjson-check 已跳过(fastjson-check.skip=true)");
            return;
        }

        List<String> targets = new ArrayList<String>();
        JarScanner scanner = new JarScanner();

        if (path != null) {
            if (!path.exists()) {
                throw new MojoExecutionException("路径不存在:" + path.getAbsolutePath());
            }
            targets.add(path.getAbsolutePath());
            scanner.scan(path);
        } else {
            for (File f : dependencyJars()) {
                scanner.scan(f);
            }
            targets.add("Maven 解析后的依赖(" + project.getArtifactId() + ")");
        }

        List<Detection> found = new ArrayList<Detection>(scanner.detections());
        Collections.sort(found, new Comparator<Detection>() {
            public int compare(Detection a, Detection b) {
                return a.severity().compareTo(b.severity());
            }
        });

        renderToLog(targets, scanner, found);

        int actionable = 0;
        for (Detection d : found) {
            if (d.severity().isActionable()) {
                actionable++;
            }
        }

        // 🔴 关掉「退出码 N」之后必须把「为什么没打红」说出来 ——
        //    否则「发现了问题但构建成功」看起来会像「工具没在干活」。
        //    (spring-eol-check 0.2.1 踩过的同一条:关掉一条会误导的信息,不等于什么都不说。)
        if (actionable > 0 && !failOnFound) {
            getLog().info("");
            // ⚠️ 这里**不要用 emoji**(原本写的是 ℹ️)：真实构件复验实测，GBK 控制台下它会显示成 `??`，
            //    看起来像乱码或 bug —— 一个自查工具的输出出现疑似乱码，会直接削弱它的可信度。
            //    报告里只用目标环境一定表示得了的字符。
            getLog().info("注意：上面有 CRITICAL/HIGH 级别的发现，但本次**没有**让构建失败"
                    + " —— fastjson-check.failOnFound 默认就是 false。");
            getLog().info("      要把它当成 CI 门禁，加 -Dfastjson-check.failOnFound=true。");
        }

        if (failOnFound && actionable > 0) {
            throw new MojoFailureException(
                    "发现 " + actionable + " 处需要立即处理的 fastjson"
                            + "(fastjson-check.failOnFound=true)");
        }
    }

    /**
     * 把报告逐行交给 Maven 的日志系统输出。
     *
     * <p>🔴 <b>必须走 {@code getLog()},不能图好看直接用 {@code System.out}</b>。
     * 本工具的报告是<b>中文</b>,而 {@code System.out} 按平台默认编码(本机 GBK)写字节、
     * 终端却是 UTF-8 → <b>整份报告全是乱码</b>。CLI 那边有 {@code --utf8/--gbk} 开关兜底,
     * 插件模式把那个开关绕过去了。
     * <b>单测测不出来</b>:单测往 {@code ByteArrayOutputStream} 写,根本不经过控制台编码。
     * (这是 spring-eol-check 真实构件复验第 12 次抓到的问题,原样适用于本工具。)
     *
     * <p>做法:先渲染进内存缓冲(显式 UTF-8),再按行 log ——
     * 字符串在交给 Maven 之前始终是 Java 的 String,不经过任何平台默认编码的字节转换。
     * 代价是每行多一个 {@code [INFO]} 前缀(前缀等宽,表格仍对得齐)—— 正确性优先于美观。
     */
    private void renderToLog(List<String> targets, JarScanner scanner, List<Detection> found)
            throws MojoExecutionException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        PrintStream saved = Main.out;
        String text;
        try {
            PrintStream ps = new PrintStream(buf, true, "UTF-8");
            Main.out = ps;
            // color=false:Maven 日志不吃 ANSI 转义,开了会在日志文件里留下乱码序列
            Main.printReport(targets, scanner, found, false);
            ps.flush();
            text = new String(buf.toByteArray(), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new MojoExecutionException("当前 JVM 不支持 UTF-8?", e);
        } finally {
            Main.out = saved;   // 复原,免得影响同一 JVM 里的后续执行(多模块构建会复用)
        }
        getLog().info("");
        for (String line : text.split("\r?\n", -1)) {
            getLog().info(line);
        }
    }

    /**
     * Maven 解析后的依赖对应的本地仓库真实 jar。
     *
     * <p>🔴 只收真实存在的文件;拿不到文件的(未解析 / pom 类型)跳过,
     * 但<b>不静默跳过</b> —— 一个都没拿到时必须让用户看见,
     * 否则「没有问题」和「什么都没检查」在输出里长得一模一样。
     */
    private List<File> dependencyJars() {
        List<File> files = new ArrayList<File>();
        int noFile = 0;
        Set<Artifact> arts = project.getArtifacts();
        if (arts != null) {
            for (Artifact a : arts) {
                File f = a.getFile();
                if (f != null && f.isFile()) {
                    files.add(f);
                } else {
                    noFile++;
                }
            }
        }
        getLog().info("fastjson-check:解析到 " + (arts == null ? 0 : arts.size())
                + " 个依赖,其中 " + files.size() + " 个拿到了本地 jar"
                + (noFile > 0 ? "," + noFile + " 个没有对应文件(已跳过)" : ""));
        return files;
    }
}
