package io.mikko.fastjsoncheck;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** 扫描器的端到端测试：真的造出 jar，再真的扫一遍。 */
public class JarScannerTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private static final String MARKER_V1 = "com/alibaba/fastjson/JSON.class";
    private static final String MARKER_V2 = "com/alibaba/fastjson2/JSON.class";

    // ---- 辅助：构造 jar ----

    private static byte[] zipBytes(Map<String, byte[]> entries) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ZipOutputStream zos = new ZipOutputStream(bos);
        for (Map.Entry<String, byte[]> e : entries.entrySet()) {
            zos.putNextEntry(new ZipEntry(e.getKey()));
            zos.write(e.getValue());
            zos.closeEntry();
        }
        zos.close();
        return bos.toByteArray();
    }

    private File writeJar(String name, Map<String, byte[]> entries) throws IOException {
        File f = tmp.newFile(name);
        OutputStream os = new FileOutputStream(f);
        os.write(zipBytes(entries));
        os.close();
        return f;
    }

    private static byte[] b(String s) {
        try {
            return s.getBytes("UTF-8");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static Map<String, byte[]> fastjson1Entries(String version) {
        Map<String, byte[]> m = new LinkedHashMap<String, byte[]>();
        m.put(MARKER_V1, b("fake"));
        m.put("META-INF/maven/com.alibaba/fastjson/pom.properties",
                b("groupId=com.alibaba\nartifactId=fastjson\nversion=" + version + "\n"));
        return m;
    }

    // ---- 测试 ----

    @Test
    public void findsFastjsonInPlainJar() throws IOException {
        File jar = writeJar("fastjson-1.2.83.jar", fastjson1Entries("1.2.83"));

        JarScanner scanner = new JarScanner();
        scanner.scan(jar);

        List<Detection> found = scanner.detections();
        org.junit.Assert.assertEquals(1, found.size());
        org.junit.Assert.assertEquals("1.2.83", found.get(0).version);
        org.junit.Assert.assertEquals(Severity.CRITICAL, found.get(0).severity());
    }

    /**
     * 核心场景：fastjson 藏在 Spring Boot fat-JAR 的 BOOT-INF/lib/ 里。
     * 这是 CVE-2026-16723 的主要在野利用场景，也是最难靠肉眼发现的地方。
     */
    @Test
    public void findsFastjsonNestedInSpringBootFatJar() throws IOException {
        byte[] innerJar = zipBytes(fastjson1Entries("1.2.83"));

        Map<String, byte[]> fat = new LinkedHashMap<String, byte[]>();
        fat.put("META-INF/MANIFEST.MF",
                b("Manifest-Version: 1.0\nMain-Class: org.springframework.boot.loader.JarLauncher\n"));
        fat.put("BOOT-INF/classes/com/example/App.class", b("fake"));
        fat.put("BOOT-INF/lib/fastjson-1.2.83.jar", innerJar);
        File app = writeJar("myapp.jar", fat);

        JarScanner scanner = new JarScanner();
        scanner.scan(app);

        List<Detection> found = scanner.detections();
        org.junit.Assert.assertEquals(1, found.size());
        Detection d = found.get(0);
        org.junit.Assert.assertEquals("1.2.83", d.version);
        org.junit.Assert.assertEquals(Severity.CRITICAL, d.severity());
        // 位置必须指出它藏在哪一层，这是本工具的核心价值
        org.junit.Assert.assertTrue("位置应包含嵌套路径，实际：" + d.location,
                d.location.contains("!/BOOT-INF/lib/fastjson-1.2.83.jar"));
    }

    /**
     * 回归测试：嵌套 jar 必须继承外层的 fat-JAR 标记。
     * BOOT-INF/lib/ 下的依赖 jar 自身不含 BOOT-INF 目录，
     * 早期版本因此漏掉了“处于主要在野利用场景”的提示。
     */
    @Test
    public void nestedJarInheritsSpringBootFatJarFlag() throws IOException {
        byte[] innerJar = zipBytes(fastjson1Entries("1.2.83"));

        Map<String, byte[]> fat = new LinkedHashMap<String, byte[]>();
        fat.put("BOOT-INF/classes/com/example/App.class", b("fake"));
        fat.put("BOOT-INF/lib/fastjson-1.2.83.jar", innerJar);
        File app = writeJar("bootapp.jar", fat);

        JarScanner scanner = new JarScanner();
        scanner.scan(app);

        org.junit.Assert.assertEquals(1, scanner.detections().size());
        org.junit.Assert.assertTrue("嵌套 jar 应继承 fat-JAR 标记",
                scanner.detections().get(0).springBootFatJar);
    }

    /** 被 shade 进宿主 jar 的情况：有 class 但没有 Maven 元数据，dependency:tree 查不到。 */
    @Test
    public void flagsShadedFastjsonWithoutMavenMetadata() throws IOException {
        Map<String, byte[]> m = new LinkedHashMap<String, byte[]>();
        m.put("com/example/sdk/Client.class", b("fake"));
        m.put(MARKER_V1, b("fake"));
        File jar = writeJar("some-sdk-3.1.0.jar", m);

        JarScanner scanner = new JarScanner();
        scanner.scan(jar);

        org.junit.Assert.assertEquals(1, scanner.detections().size());
        Detection d = scanner.detections().get(0);
        org.junit.Assert.assertTrue("应标记为疑似 shade", d.shaded);
        org.junit.Assert.assertEquals(Severity.UNKNOWN, d.severity());
    }

    /** 不含 fastjson 的 jar 绝不能误报 —— 误报会让人失去信任。 */
    @Test
    public void doesNotReportCleanJar() throws IOException {
        Map<String, byte[]> m = new LinkedHashMap<String, byte[]>();
        m.put("com/example/Clean.class", b("fake"));
        m.put("META-INF/MANIFEST.MF", b("Manifest-Version: 1.0\n"));
        File jar = writeJar("clean-app.jar", m);

        JarScanner scanner = new JarScanner();
        scanner.scan(jar);

        org.junit.Assert.assertTrue("干净 jar 不应有任何检出", scanner.detections().isEmpty());
    }

    /**
     * fastjson2 的 groupId 是 com.alibaba.fastjson2，不是 com.alibaba
     * —— 元数据路径为 META-INF/maven/com.alibaba.fastjson2/fastjson2/pom.properties。
     * 这里刻意用真实包里的路径，早期版本按 com.alibaba/fastjson2 硬编码时会漏读版本。
     */
    @Test
    public void detectsFastjson2WithItsRealGroupId() throws IOException {
        Map<String, byte[]> m = new LinkedHashMap<String, byte[]>();
        m.put(MARKER_V2, b("fake"));
        m.put("META-INF/maven/com.alibaba.fastjson2/fastjson2/pom.properties",
                b("groupId=com.alibaba.fastjson2\nartifactId=fastjson2\nversion=2.0.62\n"));
        // 文件名故意不含版本，确保版本只能来自 pom.properties
        File jar = writeJar("renamed-lib.jar", m);

        JarScanner scanner = new JarScanner();
        scanner.scan(jar);

        org.junit.Assert.assertEquals(1, scanner.detections().size());
        Detection d = scanner.detections().get(0);
        org.junit.Assert.assertEquals("fastjson2", d.artifact);
        org.junit.Assert.assertEquals("2.0.62", d.version);
        org.junit.Assert.assertEquals(Detection.VersionSource.POM_PROPERTIES, d.versionSource);
        org.junit.Assert.assertEquals(Severity.CRITICAL, d.severity());
    }

    /** fastjson 1.x 的元数据路径（groupId 为 com.alibaba），同样应能读到版本。 */
    @Test
    public void readsFastjson1VersionFromPomPropertiesWhenJarRenamed() throws IOException {
        File jar = writeJar("renamed-1x.jar", fastjson1Entries("1.2.83"));

        JarScanner scanner = new JarScanner();
        scanner.scan(jar);

        Detection d = scanner.detections().get(0);
        org.junit.Assert.assertEquals("1.2.83", d.version);
        org.junit.Assert.assertEquals(Detection.VersionSource.POM_PROPERTIES, d.versionSource);
    }

    @Test
    public void scansDirectoryRecursively() throws IOException {
        writeJar("fastjson-1.2.83.jar", fastjson1Entries("1.2.83"));
        Map<String, byte[]> clean = new LinkedHashMap<String, byte[]>();
        clean.put("com/example/Clean.class", b("fake"));
        writeJar("clean.jar", clean);

        JarScanner scanner = new JarScanner();
        scanner.scan(tmp.getRoot());

        org.junit.Assert.assertEquals(1, scanner.detections().size());
    }

    @Test
    public void extractsVersionFromJarFileName() {
        org.junit.Assert.assertEquals("1.2.83", JarScanner.versionFromJarName("fastjson-1.2.83.jar"));
        org.junit.Assert.assertEquals("2.0.62", JarScanner.versionFromJarName("fastjson2-2.0.62.jar"));
        org.junit.Assert.assertNull(JarScanner.versionFromJarName("some-sdk-3.1.0.jar"));
    }
}
