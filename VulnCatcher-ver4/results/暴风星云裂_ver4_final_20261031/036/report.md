# 落日二号乙漏洞挖掘报告 — 20261031-173102-476bd9

- 生成时间：2026-10-31T09:31:45.727033+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\036.zip`
- 输入模式：`zip`
- SHA256：`21f0b55e102a19f7e1305cfce872a6ab1e1c931079a8ad1e4b9dbafe94f87b7f`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总仅含 1 条已去重 finding：036.php 的开放重定向（open_redirect，medium，LLM-7af8cc31bcdd），位于 036.php 第 13 行附近的 header Location 输出，判定为 redirect 参数黑名单可绕过；该条带 POC（静态文本 POC，未执行、未动态验证）。最高危即此条 medium 开放重定向，无高危/严重项。POC 齐全度：1/1 finding 有 POC，但均为静态证据 POC，不能宣称可动态复现。整体覆盖极薄：仅 1 个 PHP 文件、0 个端点、无框架，且输入未提供 036.php 代码正文，注入类与配置类结论均无法落地。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 524 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 036.php（21 行），已完整审计 1-21 行。该脚本实现一个 redirect 跳转功能：从 $_GET['redirect'] 取值，经 preg_match 黑名单（仅拦 http:// / https://）后直接 header("location: " . $_GET['redirect'])。确认存在开放重定向（CWE-601），黑名单可被协议相对 URL //host、反斜杠变体、javascript:/data: 等绕过，链在 036.php:3-11 闭合。未发现命令执行、SQL、文件包含、反序列化等汇点；文件内无 md5/sha1、rand、setcookie、加密调用，故 weak_hash/weak_crypto/weak_random/insecure_cookie 无证据，不单独立项。输入中无诱导性文本，无 prompt_injection 证据。code_pack 之外文件按规则视为不存在，未覆盖 include/require 目标与运行环境配置。

未覆盖 / 证据缺口：
- 无 php.ini/Web 服务器配置，无法评估 allow_url_include、open_basedir 等对可利用性的影响
- 无部署环境与 PHP 版本信息，javascript: 伪协议在 Location 头的实际客户端行为需动态确认
- code_pack 仅 1 个文件，无法确认是否存在被 include/require 引用但未纳入清单的文件

## 3. Findings

### F-1: 036.php redirect 参数黑名单可绕过导致开放重定向（header location 注入）

- **类型**：`open_redirect` / CWE-601
- **严重度**：`medium`
- **置信度**：`0.82`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`036.php:3-13`
- **来源**：`llm_finding`

**描述**

脚本从 $_GET['redirect'] 读取跳转目标，仅用 preg_match("/http:\/\/|https:\/\//i") 做黑名单校验，禁止出现 http:// 或 https:// 子串；校验通过后直接 header("location: " . $_GET['redirect']) 输出跳转。该黑名单只匹配字面协议前缀，未做 URL 规范化、未限制为相对路径、未校验 scheme，因此可用协议相对 URL（//evil.example）、大小写/编码变体、反斜杠变体（\\evil.example）、或其它 scheme（如 javascript:、data:、ftp:）绕过，实现任意目标跳转。攻击者可构造可信域链接诱导受害者跳转到钓鱼站点，或利用 javascript: 伪协议在部分客户端触发脚本执行。

**source / sink**

- source：query `redirect`（036.php）
- sink：036.php:13 header("location: " . $_GET['redirect']) 位于 036.php:11

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `036.php:3` | 检查 GET 参数 redirect 存在且非空，攻击者完全控制其值 | 原始字符串，未过滤 |  |
| 2 | `036.php:4` | preg_match 黑名单仅匹配 http:// 或 https:// 子串，不匹配 //、\\、javascript: 等变体 | 通过校验（不含 http:// / https:// 字面量） | 黑名单只覆盖两种字面协议前缀，协议相对 URL //host、反斜杠 \\host、javascript:/data: 等均不含该子串，直接绕过 |
| 3 | `036.php:11` | 未做任何规范化或白名单，直接将攻击者字符串拼入 Location 响应头 | 原样进入 HTTP 响应头 |  |

**POC**

针对 036.php（GET 路由 /036.php）的开放重定向 POC。源码第 13 行将外部可控的 GET 参数 redirect 直接用于跳转（Location 头），未做白名单或同源校验，攻击者可诱导受害者跳转至攻击者控制的域名。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/036.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 开放重定向 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/036.php?redirect=%2F%2Fexample.com'
```
预期：响应为 30x 且 Location 指向攻击者控制的域名。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`//example.com`
- POC 目录：`poc/LLM-7af8cc31bcdd`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

开放重定向：攻击者可借助可信域链接将用户导向钓鱼/恶意站点；若客户端接受 javascript: 伪协议，可进一步执行脚本。

**CVE / CWE 论证**

CWE-601 URL 重定向到不可信站点。外部无需认证即可通过 GET 参数触发，source→sink 链在 036.php:3-11 完整闭合，黑名单可被协议相对 URL 绕过。

**修复建议**

不要直接使用用户输入作为 Location。改为服务端维护允许的跳转目标白名单（映射 ID→URL），或强制只接受站内相对路径并做规范化校验（拒绝以 //、\\、: 开头及任何 scheme）。

**验证说明**

需动态确认目标 PHP 环境对 header() 中 javascript:/协议相对 URL 的处理与浏览器行为；开放重定向本身已由源码闭合，但 javascript: 伪协议的实际执行依赖客户端。
模型 POC 要点：利用协议相对 URL 绕过 http:// 黑名单，使 Location 指向外部站点
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /036.php）：符合 CWE-601（URL 重定向到不可信站点）。漏洞位于可交付代码 036.php:13，外部输入来自查询参数 redirect，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅保留文本请求结构，不生成可自动执行的脚本；如需手工复现，请将 TARGET 替换为授权测试目标后手动发送上述原始 HTTP 请求，并重点检查响应中的 Location 头。禁止对非授权目标使用。

## 4. 二次注入（SecondOrderAnalyzer）

本次未发现 store→read→sink 闭环的二次注入链。

## 5. AWVS 联动

- 输入模式：`zip`
- 导入结果：0 条
- 关联明细：0 条
- 目标种子：`awvs/targets.json`
- 说明：AWVS 是外部动态扫描器；本管线只导入其结果做佐证，或导出端点供 AWVS 播种。

## 6. 漏洞类型覆盖

| 类型 | CWE | AutoCVE | 本次数量 |
|---|---|---|---|
| `command_injection` | CWE-78 | 是 | 0 |
| `sql_injection` | CWE-89 | 是 | 0 |
| `ssrf` | CWE-918 | 是 | 0 |
| `path_traversal` | CWE-22 | 是 | 0 |
| `deserialization` | CWE-502 | 是 | 0 |
| `ssti` | CWE-1336 | 是 | 0 |
| `auth_bypass` | CWE-287 | 是 | 0 |
| `idor` | CWE-639 | 是 | 0 |
| `xxe` | CWE-611 | 是 | 0 |
| `xss` | CWE-79 | 是 | 0 |
| `business_logic` | CWE-840 | 是 | 0 |
| `other` | CWE-693 | 是 | 0 |
| `rce` | CWE-94 |  | 0 |
| `code_injection` | CWE-94 |  | 0 |
| `expression_injection` | CWE-917 |  | 0 |
| `ldap_injection` | CWE-90 |  | 0 |
| `xpath_injection` | CWE-643 |  | 0 |
| `open_redirect` | CWE-601 |  | 1 |
| `csrf` | CWE-352 |  | 0 |
| `file_upload` | CWE-434 |  | 0 |
| `race_condition` | CWE-367 |  | 0 |
| `weak_crypto` | CWE-327 |  | 0 |
| `weak_hash` | CWE-328 |  | 0 |
| `weak_random` | CWE-330 |  | 0 |
| `hardcoded_secret` | CWE-798 |  | 0 |
| `trust_boundary` | CWE-501 |  | 0 |
| `log_injection` | CWE-117 |  | 0 |
| `insecure_cookie` | CWE-614 |  | 0 |
| `information_disclosure` | CWE-200 |  | 0 |
| `api_info_disclosure` | CWE-200 |  | 0 |
| `captcha_bypass` | CWE-804 |  | 0 |
| `csp` | CWE-693 |  | 0 |
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.94 | 是 |
| surface_mapper | 攻击面测绘 | 8.23 | 是 |
| deep_finder | LLM 深挖 | 8.14 | 是 |
| candidate_screener | 候选筛选 | 3.6 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.31 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.74 | 是 |
| coordinator | 管线协调 | 5.82 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
