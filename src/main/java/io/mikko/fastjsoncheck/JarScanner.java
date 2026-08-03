package io.mikko.fastjsoncheck;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * 扫描器：在 jar / war / 目录中寻找 fastjson。
 *
 * <p>关键能力是<b>递归进入嵌套 jar</b>。Spring Boot fat-JAR 把所有依赖打包进
 * {@code BOOT-INF/lib/} 下，传统做法必须先解压才能看清里面有什么；
 * 而 CVE-2026-16723 的在野利用恰恰主要发生在 fat-JAR 部署上。
 * 本扫描器直接在内存里逐层展开，不落地、不解压。
 */
public class JarScanner {

    /** fastjson 1.x 的标志性 class 路径。 */
    private static final String MARKER_V1 = "com/alibaba/fastjson/JSON.class";
    /** fastjson 2.x 的标志性 class 路径。 */
    private static final String MARKER_V2 = "com/alibaba/fastjson2/JSON.class";

    /*
     * Maven 元数据路径里的 groupId 不能写死：
     *   fastjson 1.x 是 com.alibaba        -> META-INF/maven/com.alibaba/fastjson/pom.properties
     *   fastjson2   是 com.alibaba.fastjson2 -> META-INF/maven/com.alibaba.fastjson2/fastjson2/pom.properties
     * 早期版本按 com.alibaba/fastjson2 硬编码，导致 fastjson2 只能从文件名取版本，
     * 一旦 jar 被重命名就取不到。这里改为匹配任意 groupId。
     */
    private static final Pattern POM_V1 =
            Pattern.compile("^META-INF/maven/[^/]+/fastjson/pom\\.properties$");
    private static final Pattern POM_V2 =
            Pattern.compile("^META-INF/maven/[^/]+/fastjson2/pom\\.properties$");

    /** 从 jar 文件名提取版本，如 fastjson-1.2.83.jar、fastjson2-2.0.62.jar。 */
    private static final Pattern JAR_NAME_VERSION =
            Pattern.compile("^fastjson2?-(\\d+(?:\\.\\d+)*(?:[._-][A-Za-z0-9]+)*)\\.jar$");

    /** 嵌套 jar 单个条目的读取上限，防止畸形/超大包撑爆内存。 */
    private static final long MAX_NESTED_ENTRY_BYTES = 64L * 1024 * 1024;

    /** 嵌套递归深度上限，防御 zip 套娃。 */
    private static final int MAX_DEPTH = 8;

    private final List<Detection> detections = new ArrayList<Detection>();
    private final List<String> warnings = new ArrayList<String>();
    private int scannedArchives;

    public List<Detection> detections() {
        return detections;
    }

    public List<String> warnings() {
        return warnings;
    }

    public int scannedArchives() {
        return scannedArchives;
    }

    /** 扫描一个路径，可以是 jar/war 文件，也可以是目录（递归查找归档文件）。 */
    public void scan(File target) {
        if (!target.exists()) {
            warnings.add("路径不存在：" + target.getPath());
            return;
        }
        if (target.isDirectory()) {
            scanDirectory(target);
        } else if (isArchive(target.getName())) {
            scanArchiveFile(target);
        } else {
            warnings.add("跳过（不是 jar/war/zip）：" + target.getPath());
        }
    }

    private void scanDirectory(File dir) {
        File[] children = dir.listFiles();
        if (children == null) {
            warnings.add("目录无法读取：" + dir.getPath());
            return;
        }
        for (File child : children) {
            if (child.isDirectory()) {
                scanDirectory(child);
            } else if (isArchive(child.getName())) {
                scanArchiveFile(child);
            }
        }
    }

    private void scanArchiveFile(File file) {
        InputStream in = null;
        try {
            in = new FileInputStream(file);
            scanArchiveStream(in, file.getPath(), file.getName(), 0, false);
        } catch (IOException e) {
            warnings.add("读取失败 " + file.getPath() + "：" + e.getMessage());
        } finally {
            closeQuietly(in);
        }
    }

    /**
     * 扫描一个归档流。
     *
     * @param in          归档内容流
     * @param location    展示用的逻辑路径（嵌套时形如 a.jar!/BOOT-INF/lib/b.jar）
     * @param archiveName 当前归档的文件名，用于从名字里推断版本
     * @param depth       当前递归深度
     * @param inFatJar    外层是否为 Spring Boot fat-JAR。必须向下传递：
     *                    BOOT-INF/lib/ 里的依赖 jar 自身并不含 BOOT-INF 目录，
     *                    若不继承这个标记，就会漏掉“处于主要在野利用场景”的提示
     */
    private void scanArchiveStream(InputStream in, String location, String archiveName, int depth,
                                   boolean inFatJar) throws IOException {
        if (depth > MAX_DEPTH) {
            warnings.add("嵌套层级超过上限，已停止深入：" + location);
            return;
        }
        scannedArchives++;

        boolean hasV1Marker = false;
        boolean hasV2Marker = false;
        String versionFromPomV1 = null;
        String versionFromPomV2 = null;
        boolean springBootFatJar = false;
        // 嵌套 jar 要等外层遍历完再处理，先缓存起来（同一个 ZipInputStream 不能并发读）
        List<NestedArchive> nested = new ArrayList<NestedArchive>();

        ZipInputStream zis = new ZipInputStream(in);
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            String name = entry.getName();

            if (name.startsWith("BOOT-INF/")) {
                springBootFatJar = true;
            }

            if (MARKER_V1.equals(name)) {
                hasV1Marker = true;
            } else if (MARKER_V2.equals(name)) {
                hasV2Marker = true;
            } else if (POM_V2.matcher(name).matches()) {
                // 先判 V2：fastjson2 的路径也含 "fastjson"，顺序反了会被 V1 规则误吞
                versionFromPomV2 = readVersionFromPomProperties(zis);
            } else if (POM_V1.matcher(name).matches()) {
                versionFromPomV1 = readVersionFromPomProperties(zis);
            } else if (!entry.isDirectory() && isArchive(name)) {
                long size = entry.getSize();
                if (size > MAX_NESTED_ENTRY_BYTES) {
                    warnings.add("嵌套包过大已跳过（" + size + " 字节）：" + location + "!/" + name);
                    continue;
                }
                byte[] bytes = readAllBytes(zis, MAX_NESTED_ENTRY_BYTES);
                if (bytes != null) {
                    nested.add(new NestedArchive(name, bytes));
                }
            }
        }

        boolean fatJarContext = springBootFatJar || inFatJar;

        // 当前这层归档自身是否包含 fastjson
        if (hasV1Marker) {
            record(location, archiveName, "fastjson", versionFromPomV1, fatJarContext);
        }
        if (hasV2Marker) {
            record(location, archiveName, "fastjson2", versionFromPomV2, fatJarContext);
        }

        // 再逐个深入嵌套包
        for (NestedArchive na : nested) {
            String childLocation = location + "!/" + na.entryName;
            String childName = na.entryName.substring(na.entryName.lastIndexOf('/') + 1);
            try {
                scanArchiveStream(new ByteArrayInputStream(na.content), childLocation, childName,
                        depth + 1, fatJarContext);
            } catch (IOException e) {
                warnings.add("嵌套包读取失败 " + childLocation + "：" + e.getMessage());
            }
        }
    }

    private void record(String location, String archiveName, String artifact,
                        String versionFromPom, boolean springBootFatJar) {
        String version = versionFromPom;
        Detection.VersionSource source = Detection.VersionSource.POM_PROPERTIES;

        if (version == null) {
            version = versionFromJarName(archiveName);
            source = version != null ? Detection.VersionSource.FILE_NAME : Detection.VersionSource.UNKNOWN;
        }

        // 有 class 却没有 Maven 元数据 —— 典型的被 shade 进宿主 jar 的情况。
        // 这类最危险：mvn dependency:tree 看不见它。
        boolean shaded = versionFromPom == null && !looksLikeFastjsonJar(archiveName);

        VersionRules.Verdict verdict = VersionRules.judge(version);
        detections.add(new Detection(location, artifact, version, source, shaded, springBootFatJar, verdict));
    }

    private static String readVersionFromPomProperties(InputStream in) {
        byte[] bytes = readAllBytes(in, 64 * 1024);
        if (bytes == null) {
            return null;
        }
        java.util.Properties props = new java.util.Properties();
        try {
            props.load(new ByteArrayInputStream(bytes));
        } catch (IOException e) {
            return null;
        }
        String v = props.getProperty("version");
        return (v != null && !v.trim().isEmpty()) ? v.trim() : null;
    }

    static String versionFromJarName(String jarName) {
        if (jarName == null) {
            return null;
        }
        Matcher m = JAR_NAME_VERSION.matcher(jarName);
        return m.matches() ? m.group(1) : null;
    }

    private static boolean looksLikeFastjsonJar(String jarName) {
        return jarName != null && jarName.startsWith("fastjson") && jarName.endsWith(".jar");
    }

    static boolean isArchive(String name) {
        if (name == null) {
            return false;
        }
        String lower = name.toLowerCase();
        return lower.endsWith(".jar") || lower.endsWith(".war") || lower.endsWith(".ear");
    }

    /** 读取流的全部内容，超过上限则放弃并返回 null。 */
    private static byte[] readAllBytes(InputStream in, long limit) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            long total = 0;
            int n;
            while ((n = in.read(buf)) > 0) {
                total += n;
                if (total > limit) {
                    return null;
                }
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }

    private static void closeQuietly(InputStream in) {
        if (in != null) {
            try {
                in.close();
            } catch (IOException ignored) {
                // 关闭失败不影响结果
            }
        }
    }

    /** 暂存待深入扫描的嵌套归档。 */
    private static final class NestedArchive {
        final String entryName;
        final byte[] content;

        NestedArchive(String entryName, byte[] content) {
            this.entryName = entryName;
            this.content = content;
        }
    }
}
