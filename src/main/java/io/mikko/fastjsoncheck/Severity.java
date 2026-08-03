package io.mikko.fastjsoncheck;

/** 风险等级。顺序即严重性从高到低，用于排序与决定进程退出码。 */
public enum Severity {
    CRITICAL("CRITICAL"),
    HIGH("HIGH"),
    MEDIUM("MEDIUM"),
    OK("OK"),
    UNKNOWN("UNKNOWN");

    private final String label;

    Severity(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    /** CRITICAL 与 HIGH 视为“需要立即处理”，决定退出码是否非 0（便于接入 CI）。 */
    public boolean isActionable() {
        return this == CRITICAL || this == HIGH;
    }
}
