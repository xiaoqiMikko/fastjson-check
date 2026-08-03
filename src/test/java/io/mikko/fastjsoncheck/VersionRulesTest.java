package io.mikko.fastjsoncheck;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * 版本判定规则的测试。
 *
 * <p>这是整个工具唯一“会说错话”的地方 —— 判错了就会让人误以为安全，
 * 所以边界值必须逐个钉死。
 */
public class VersionRulesTest {

    // ---- fastjson 1.x：CVE-2026-16723 区间 1.2.68 ~ 1.2.83 ----

    @Test
    public void lowerBoundOfCveRangeIsCritical() {
        assertEquals(Severity.CRITICAL, VersionRules.judge("1.2.68").severity);
    }

    @Test
    public void upperBoundOfCveRangeIsCritical() {
        assertEquals(Severity.CRITICAL, VersionRules.judge("1.2.83").severity);
    }

    @Test
    public void insideCveRangeIsCritical() {
        assertEquals(Severity.CRITICAL, VersionRules.judge("1.2.75").severity);
        assertEquals(Severity.CRITICAL, VersionRules.judge("1.2.80").severity);
    }

    @Test
    public void justBelowCveRangeIsHighNotCritical() {
        // 1.2.67 不受 CVE-2026-16723 影响，但 1.x 已 EOL，仍需迁移
        assertEquals(Severity.HIGH, VersionRules.judge("1.2.67").severity);
    }

    @Test
    public void oldOneXVersionsAreStillHigh() {
        assertEquals(Severity.HIGH, VersionRules.judge("1.2.24").severity);
        assertEquals(Severity.HIGH, VersionRules.judge("1.1.15").severity);
    }

    /** 阿里发过 1.2.83_noneautotype 这类带后缀的包，不能因为后缀就判错。 */
    @Test
    public void suffixedVersionsStillMatchCveRange() {
        assertEquals(Severity.CRITICAL, VersionRules.judge("1.2.83_noneautotype").severity);
        assertEquals(Severity.CRITICAL, VersionRules.judge("1.2.83.sec01").severity);
        assertEquals(Severity.CRITICAL, VersionRules.judge("1.2.70-SNAPSHOT").severity);
    }

    // ---- fastjson 2.x：≤2.0.62 有 RCE，2.0.63 起安全 ----

    @Test
    public void fastjson2AtOrBelow62IsCritical() {
        assertEquals(Severity.CRITICAL, VersionRules.judge("2.0.62").severity);
        assertEquals(Severity.CRITICAL, VersionRules.judge("2.0.61").severity);
        assertEquals(Severity.CRITICAL, VersionRules.judge("2.0.1").severity);
        assertEquals(Severity.CRITICAL, VersionRules.judge("2.0.0").severity);
    }

    @Test
    public void fastjson2FixedVersionIsOk() {
        assertEquals(Severity.OK, VersionRules.judge("2.0.63").severity);
    }

    @Test
    public void fastjson2NewerThanFixedIsOk() {
        assertEquals(Severity.OK, VersionRules.judge("2.0.64").severity);
        assertEquals(Severity.OK, VersionRules.judge("2.1.0").severity);
        assertEquals(Severity.OK, VersionRules.judge("2.0.100").severity);
    }

    // ---- 无法判定的情况，必须老实说不知道，不能猜 ----

    @Test
    public void nullOrBlankVersionIsUnknown() {
        assertEquals(Severity.UNKNOWN, VersionRules.judge(null).severity);
        assertEquals(Severity.UNKNOWN, VersionRules.judge("").severity);
        assertEquals(Severity.UNKNOWN, VersionRules.judge("   ").severity);
    }

    @Test
    public void unparseableVersionIsUnknown() {
        assertEquals(Severity.UNKNOWN, VersionRules.judge("abc").severity);
        assertEquals(Severity.UNKNOWN, VersionRules.judge("unknown").severity);
    }

    @Test
    public void unexpectedMajorVersionIsUnknown() {
        assertEquals(Severity.UNKNOWN, VersionRules.judge("3.0.0").severity);
    }

    // ---- 版本比较：数值段比较，不能按字符串比 ----

    @Test
    public void comparesNumericallyNotLexically() {
        // 字符串比较会认为 "1.2.9" > "1.2.10"，这是典型错误
        assertTrue(VersionRules.compare("1.2.10", "1.2.9") > 0);
        assertTrue(VersionRules.compare("2.0.100", "2.0.63") > 0);
        assertTrue(VersionRules.compare("1.2.68", "1.2.68") == 0);
        assertTrue(VersionRules.compare("1.2.67", "1.2.68") < 0);
    }

    @Test
    public void comparesDifferentSegmentCounts() {
        assertTrue(VersionRules.compare("2.0", "2.0.0") == 0);
        assertTrue(VersionRules.compare("2.0.1", "2.0") > 0);
    }

    // ---- 版本号解析 ----

    @Test
    public void parseStopsAtNonNumericSuffix() {
        int[] v = VersionRules.parse("1.2.83_noneautotype");
        assertEquals(3, v.length);
        assertEquals(1, v[0]);
        assertEquals(2, v[1]);
        assertEquals(83, v[2]);
    }

    @Test
    public void parseHandlesLeadingV() {
        int[] v = VersionRules.parse("v2.0.63");
        assertEquals(2, v[0]);
        assertEquals(0, v[1]);
        assertEquals(63, v[2]);
    }

    // ---- 判定结果必须带可执行建议，不能只报警不给出路 ----

    @Test
    public void everyVerdictCarriesReasonAndAdvice() {
        String[] samples = {"1.2.83", "1.2.60", "2.0.62", "2.0.63", null, "garbage"};
        for (String s : samples) {
            VersionRules.Verdict v = VersionRules.judge(s);
            assertTrue("reason 不能为空：" + s, v.reason != null && !v.reason.isEmpty());
            assertTrue("advice 不能为空：" + s, v.advice != null && !v.advice.isEmpty());
        }
    }
}
