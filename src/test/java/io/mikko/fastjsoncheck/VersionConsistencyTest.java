package io.mikko.fastjsoncheck;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.parsers.DocumentBuilderFactory;
import org.junit.Test;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * jar 自报的版本号必须与 pom 的版本号一致。
 *
 * <p>🔴 由来(2026-09-09,㊵ 那轮):升 pom 版本发 Release 时,{@code Main.VERSION}
 * 是**独立的一个字面量**,不会跟着走 —— 于是 v0.1.2 的 Release 里可以装着一个
 * 自称 0.1.1 的 jar,而**构建全绿**。这条规矩本来只能靠人记得同步,现在由本测试强制:
 * 对不上,构建当场失败。
 *
 * <p>☠️ **2026-09-10 补**:㊵ 那轮把这个测试加给了 12 个仓库,而本仓库不在那 12 个里 ——
 * 和 `exit_code_check.py` 的 REPOS 漏掉本仓库是**同一个洞**:
 * 兜底机制本身也有覆盖面,而覆盖面没有任何东西在守。
 */
public class VersionConsistencyTest {

    @Test
    public void Main里的VERSION必须等于pom的版本号() throws Exception {
        // pom 的版本:取根节点的直接子元素 <version>,不匹配依赖里的同名标签
        Element root = DocumentBuilderFactory.newInstance()
                .newDocumentBuilder().parse(new File("pom.xml")).getDocumentElement();
        String pomVersion = null;
        for (Node n = root.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() == Node.ELEMENT_NODE && "version".equals(n.getNodeName())) {
                pomVersion = n.getTextContent().trim();
                break;
            }
        }
        assertTrue("pom.xml 根节点下没读到 <version>,本测试失去意义,不许当通过",
                pomVersion != null && !pomVersion.isEmpty());

        // 源码里的版本:直接读字面量,不走反射 —— 不依赖 VERSION 的可见性
        String src = new String(Files.readAllBytes(
                Paths.get("src/main/java/io/mikko/fastjsoncheck/Main.java")), StandardCharsets.UTF_8);
        Matcher m = Pattern.compile("VERSION\\s*=\\s*\"([^\"]+)\"").matcher(src);
        assertTrue("Main.java 里没找到 VERSION 字面量 —— 找不到就不是通过,是判据坏了", m.find());

        assertEquals("Main.VERSION 与 pom 版本不一致:发出去的 jar 会自报一个错的版本号",
                pomVersion, m.group(1));
    }
}
