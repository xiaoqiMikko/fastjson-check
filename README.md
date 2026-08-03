# fastjson-check

[![Release](https://img.shields.io/github/v/release/xiaoqiMikko/fastjson-check)](../../releases)
[![Downloads](https://img.shields.io/github/downloads/xiaoqiMikko/fastjson-check/total)](../../releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Java](https://img.shields.io/badge/Java-8%2B-orange)](#构建)

**一条命令，查清你的 Java 应用里到底有没有 fastjson、藏在哪、是否受 CVE-2026-16723 影响。**

零依赖 · 完全离线 · 单个 23KB 的 jar · 支持 Java 8+

[English](#english) | [下载](../../releases)

---

## 为什么需要它

2026 年 7 月 21 日，fastjson 官方公布 **CVE-2026-16723**（CVSS **9.0**，远程代码执行）：

- 影响 **fastjson 1.2.68 ~ 1.2.83**
- **默认配置即可利用** —— 不需要开启 AutoType，不需要 classpath gadget，不需要认证
- 公告数日内即出现在野利用，主要针对 **Spring Boot fat-JAR** 部署

### ⚠️ 官方补丁 1.2.84 已发布，但几乎没人知道

大量安全通告（含多家英文安全媒体）至今仍称「1.x 已 EOL、**永远不会有补丁**、只能迁移到 fastjson2」。
**该说法自 2026-07-29 起已不成立。** 可自行核验：

| 证据 | 链接 |
|---|---|
| Maven 中央仓库有 `com.alibaba:fastjson:1.2.84`，jar 上传于 2026-07-29 | [repo1](https://repo1.maven.org/maven2/com/alibaba/fastjson/1.2.84/) |
| GitHub release `1.2.84`，发布于 2026-07-29T08:24:51Z | [release](https://github.com/alibaba/fastjson/releases/tag/1.2.84) |
| 关键提交 `fix: strengthen autoType type name validation and whitelist verification` | 2026-07-29T07:02:55Z |

1.2.83 发布于 2022 年 5 月，此后 1.x 分支**四年无提交** —— 1.2.84 是为本次漏洞专门破例发布的。

**为什么外界不知道**：官方是**静默发布**。1.2.83 的 release 标题标注了「（安全修复）」，
而 1.2.84 只写「1.2.84版本发布」，全文未提安全，因此没有被安全媒体和扫描器及时跟进。

👉 **对 1.x 用户的实际影响**：升级到 **1.2.84** 是成本最低的处置（同分支小版本，通常无需改代码），
不必被迫立刻做 fastjson2 的大版本迁移。本工具已按此给出建议。

而最麻烦的一点是：

> fastjson 通常是**传递依赖** —— 没人主动装它，它是被别的库捎带进来的。
> **很多团队根本不知道自己在用它。**

`mvn dependency:tree` 能列出依赖，但对两种情况无能为力：

1. 你手上只有一个打包好的 **fat-JAR**，没有源码和构建环境（线上应急排查最常见的场景）
2. fastjson 被 **shade 进了某个 SDK 的 jar 里**，依赖树上根本看不到它

本工具就是为这两种情况写的。

## 快速开始

从 [Releases](../../releases) 下载 `fastjson-check.jar`，然后：

```bash
# 扫一个 jar（Spring Boot fat-JAR 会自动逐层展开）
java -jar fastjson-check.jar ./myapp.jar

# 扫一整个目录（递归查找所有 jar/war）
java -jar fastjson-check.jar /opt/apps

# 输出 JSON，接入流水线
java -jar fastjson-check.jar /opt/apps --json
```

不需要安装、不需要账号、不联网、不上传任何数据。

## 输出长这样

```
fastjson-check 0.1.0  —— fastjson 应急排查（离线，不外传任何数据）

扫描目标：myapp.jar
已展开归档：3 个

发现 2 处 fastjson：

[CRITICAL] fastjson 1.2.83
  位置　　：myapp.jar!/BOOT-INF/lib/fastjson-1.2.83.jar
  版本来源：pom.properties
  场景　　：Spring Boot fat-JAR  ← CVE-2026-16723 的主要在野利用场景
  结论　　：命中 CVE-2026-16723（CVSS 9.0 远程代码执行），默认配置即可利用
  处置　　：1.x 已停止维护，不会有修复版本。应急处置二选一：①（推荐）迁移至
            fastjson2 2.0.63 或更高版本；② 无法立即迁移时，先启用 SafeMode
            彻底关闭 AutoType 以缓解，但这不是长期方案。

[UNKNOWN] fastjson 版本未知
  位置　　：myapp.jar!/BOOT-INF/lib/some-sdk-3.1.0.jar
  版本来源：未知
  场景　　：Spring Boot fat-JAR  ← CVE-2026-16723 的主要在野利用场景
  注意　　：疑似被 shade 进宿主 jar（有 class 但无 Maven 元数据），mvn dependency:tree 查不到它
  结论　　：无法确定 fastjson 版本

汇总：CRITICAL 1　UNKNOWN 1
```

注意第二条 —— 那个 `some-sdk-3.1.0.jar` 把 fastjson 打包进了自己内部，**依赖树上完全看不见**。

## 判定规则

| 版本 | 判定 | 说明 |
|---|---|---|
| fastjson **1.2.68 ~ 1.2.83** | 🔴 CRITICAL | 命中 CVE-2026-16723，**升 1.2.84 即可修复** |
| fastjson **≥ 1.2.84** | 🟢 OK | 已含官方修复（2026-07-29 发布） |
| fastjson **&lt; 1.2.68** | 🟠 HIGH | 不中本次 CVE，但有历史 AutoType RCE 系列漏洞 |
| fastjson2 **≤ 2.0.62** | 🔴 CRITICAL | 多态反序列化 RCE（seeAlso 路径），默认配置即可触发 |
| fastjson2 **≥ 2.0.63** | 🟢 OK | 当前推荐版本 |

⚠️ **特别注意**：官方推荐的迁移目标 fastjson2 自身在 ≤2.0.62 时也有 RCE。
「已经迁到 fastjson2」**不等于**安全，必须同时看版本号。

## 选项

```
--json        输出 JSON，便于接入流水线（恒为 UTF-8）
--utf8        强制以 UTF-8 输出（控制台中文乱码时用）
--gbk         强制以 GBK 输出（控制台中文乱码时用）
--no-color    关闭彩色输出
-h, --help    显示帮助
-v, --version 显示版本
```

**退出码**：`0` = 未发现需处理项；`1` = 发现 CRITICAL/HIGH；`2` = 用法错误。
可直接用于 CI 门禁：

```bash
java -jar fastjson-check.jar ./build/libs --json || echo "发现高危依赖，阻断发布"
```

## 它不是什么

诚实说明边界，免得误以为安全：

- **它不是通用 SCA 工具**。只查 fastjson 一个库，不查其他 CVE。要全面的依赖安全扫描，请用 Snyk / OWASP Dependency-Check 等
- **改了包名的 relocate 打包检测不到**。本工具靠 `com/alibaba/fastjson(2)/JSON.class` 这个路径识别；如果某个库在 shade 时把包名改成了 `com.foo.shaded.fastjson`，就查不出来
- **它不判断可达性**。发现依赖存在 ≠ 一定能被攻击，是否真的可利用取决于是否有外部可控的 JSON 输入路径。但在应急阶段，先把「有没有」查清楚是第一步
- **它不改你的代码**。只报告，不动手

## 构建

```bash
mvn clean package
# 产物：target/fastjson-check.jar
```

编译目标为 Java 8，因此打出来的 jar 可以直接丢到还在跑 JRE 8 的老机器上执行。
运行时零依赖 —— 一个排查工具不该再往目标环境里塞任何东西（尤其不该塞 JSON 库，我们查的就是它）。

## 反馈

**发现误报或漏报，请开一个 [Issue](../../issues)。** 安全工具最怕的就是让人误以为安全，任何一条误判都值得提。

提 issue 时如果能附上这些信息，定位会快很多：

- 用的哪个 JDK 版本、什么操作系统
- `java -jar fastjson-check.jar <目标> --json` 的输出（JSON 里不含任何路径以外的敏感信息）
- 如果方便，说明那个 jar 是怎么打包的（Spring Boot fat-JAR / shade / 普通 jar）

功能建议、新的 fastjson 相关 CVE、企业批量排查场景的需求，同样欢迎开 issue 讨论。

## 许可证

Apache License 2.0

---

<a name="english"></a>

# fastjson-check (English)

**One command to find out whether your Java application ships fastjson, where it hides, and whether you are exposed to CVE-2026-16723.**

Zero dependencies · fully offline · a single 22KB jar · Java 8+

## Why

On 2026-07-21 a remote code execution flaw in fastjson was disclosed as **CVE-2026-16723** (CVSS **9.0**):

- Affects **fastjson 1.2.68 – 1.2.83**
- Exploitable under **stock default configuration** — no AutoType, no classpath gadget, no authentication needed
- Exploited in the wild within days, primarily against **Spring Boot fat-JAR** deployments

### ⚠️ A patch does exist: 1.2.84. Almost nobody knows.

Most advisories — including major security outlets — still state that fastjson 1.x is EOL,
that **no patch will ever ship**, and that migrating to fastjson2 is the only option.
**That has been untrue since 2026-07-29.** Verify it yourself:

| Evidence | Link |
|---|---|
| `com.alibaba:fastjson:1.2.84` on Maven Central, jar uploaded 2026-07-29 | [repo1](https://repo1.maven.org/maven2/com/alibaba/fastjson/1.2.84/) |
| GitHub release `1.2.84`, published 2026-07-29T08:24:51Z | [release](https://github.com/alibaba/fastjson/releases/tag/1.2.84) |
| Commit `fix: strengthen autoType type name validation and whitelist verification` | 2026-07-29T07:02:55Z |

1.2.83 shipped in May 2022. The 1.x branch then saw **no commits for four years** —
1.2.84 was cut specifically for this vulnerability.

**Why it went unnoticed:** it was a *silent* release. The 1.2.83 release is titled
"（安全修复）" — *security fix*. The 1.2.84 release is titled merely "1.2.84版本发布"
and never mentions security, so trackers and media did not pick it up.

👉 **What this means for you:** upgrading to **1.2.84** is a patch-level bump on the same
branch and usually requires no code changes. You are not forced into an immediate
fastjson2 major migration. This tool recommends accordingly.

The hard part:

> fastjson usually arrives as a **transitive dependency** — nobody installed it on purpose.
> **Many teams do not even realise they are running it.**

`mvn dependency:tree` cannot help when you only have a packaged fat-JAR on a production box,
or when fastjson has been **shaded into some vendor SDK** and never appears in the tree at all.

## Usage

```bash
java -jar fastjson-check.jar ./myapp.jar     # scan a jar (fat-JARs are unpacked recursively, in memory)
java -jar fastjson-check.jar /opt/apps       # scan a directory
java -jar fastjson-check.jar /opt/apps --json
```

Exit code `0` = nothing actionable, `1` = CRITICAL/HIGH found, `2` = usage error.

## Verdicts

| Version | Verdict |
|---|---|
| fastjson **1.2.68 – 1.2.83** | CRITICAL — CVE-2026-16723, **fixed by upgrading to 1.2.84** |
| fastjson **≥ 1.2.84** | OK — contains the official fix (released 2026-07-29) |
| fastjson **&lt; 1.2.68** | HIGH — not this CVE, but historic AutoType RCE issues |
| fastjson2 **≤ 2.0.62** | CRITICAL — polymorphic deserialization RCE |
| fastjson2 **≥ 2.0.63** | OK |

⚠️ Migrating to fastjson2 is **not** sufficient on its own: releases up to 2.0.62 carry their own RCE.

## Limitations

- Single-purpose: it looks for fastjson only, it is not a general SCA scanner
- Cannot detect relocated/renamed packages (detection keys on `com/alibaba/fastjson(2)/JSON.class`)
- Reports presence, not reachability
- Never modifies anything

## License

Apache License 2.0
