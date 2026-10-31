# 落日二号乙漏洞挖掘报告 — 20261031-214943-b3f9e3

- 生成时间：2026-10-31T13:50:22.256442+00:00
- 输入：`$WORKSPACE\暴风星云裂\047.zip`
- 输入模式：`zip`
- SHA256：`3fb7cef196d058e1429319161506d9b7757247c40a8879ee94ca463b3d47eead`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.5.0-ver5
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总仅含 1 条已去重 finding：047.php 的 weak_id（CWE-330 弱 ID / 可预测会话标识），严重度 high，带 POC（静态证据型，非 HTTP 动态复现）。最高危即该条。POC 齐全度为 1/1，但证据等级为规则命中 + 文件级元数据，未做动态验证。攻击面测绘指出 047.php 为唯一入口、13 行、source_hot_file 命中第 1 行，但 sink_hot_files 为空，且未提供任何代码片段，因此注入/文件操作/加密类结论均无法确认。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 378 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 047.php（13 行，已完整展示 1-13 行）。逐行审计结果：第 5 行读取 $_SERVER['REQUEST_METHOD'] 仅用于判断是否为 POST，属于服务端自身元数据，不构成攻击者可控污点；第 6-9 行对 $_SESSION['last_session_id'] 做初始化与自增，值完全由服务端会话状态派生，攻击者无法注入任意内容；第 10-11 行将该自增整数写入 setcookie("dvwaSession", $cookie_value)，未设置 secure/httponly/samesite 标志。该 setcookie 缺少安全标志属于 insecure_cookie 类配置问题，但：1) 脚本未调用 session_start()，$_SESSION 在此上下文中不可用，实际行为取决于运行环境；2) 该 Cookie 值仅为服务端自增计数器，不含会话标识或敏感凭据，缺少 httponly 无法导致会话窃取或权限提升；3) 无任何 source→sink 危险汇点（无 SQL、命令、文件、反序列化、模板、SSRF、include/eval）。因此不构成 CVE 级别、可被赏金平台接收的漏洞，按零容忍误报原则不产出 finding。未闭合线索：脚本是否被其他入口 include、是否存在 session_start() 前置、Web 服务器对 Cookie 的处理策略，均超出 code_pack 范围，无法确认。

未覆盖 / 证据缺口：
- 047.php 未调用 session_start()，$_SESSION 可用性依赖外部包含或 auto_start 配置，无法从 code_pack 确认
- 无 HTTP 端点清单与部署配置，无法确认脚本对外可达性
- setcookie 缺少 secure/httponly/samesite 属配置类弱项，但 Cookie 值非敏感凭据，未达 CVE 门槛

## 3. Findings

### F-1: 047.php 会话标识可预测（CWE-330 弱 ID / 可预测会话标识）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.43`
- **结论**：`candidate` / 证据等级 `externally_corroborated`
- **位置**：`047.php:5-6`
- **来源**：`rule`

**描述**

证据仅覆盖 047.php 第 5-7 行：第 5 行判断 REQUEST_METHOD 为 POST 后，第 6 行检查 $_SESSION['last_session_id'] 是否已设置，第 7 行在未设置时将其初始化为 0。候选将其归类为「会话标识由时间/递增值派生」，但输入片段中并未出现任何会话 ID 生成代码（无 session_id()、无 mt_rand/rand/time 派生、无 setcookie 写入 dvwaSession），也未出现递增赋值语句（如 $_SESSION['last_session_id']++）。因此「可预测会话标识」这一结论在给定证据下无法闭合：last_session_id 只是一个会话内计数器/状态变量，其本身不是会话标识，且片段未展示它被用作认证凭据或写入 Cookie。攻击者输入面（POST 请求）与危险汇点（会话标识生成/接受）之间的链路在 code_pack 中缺失。

**source / sink**

- source：session `dvwaSession`（047.php）
- sink：047.php:6 	if (!isset ($_SESSION['last_session_id'])) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `047.php:6` | 会话标识由时间/递增值派生；需跨请求预测并确认服务端接受 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /047（POST）的 弱 ID / 可预测会话标识 POC。注入点：POST 会话建立请求；连续请求比较 dvwaSession Cookie；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/047'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **在保持同一会话的情况下第一次 POST，记录 Set-Cookie**

```http
curl -sS -i -b "${cookie_jar}" -c "${cookie_jar}" -X POST 'http://TARGET:8080/047' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：返回 dvwaSession 等会话 Cookie，记录其值

3. **保持同一会话再次 POST，并比较两次会话 Cookie**

```http
curl -sS -i -b "${cookie_jar}" -c "${cookie_jar}" -X POST 'http://TARGET:8080/047' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：Cookie 值出现连续递增/可预测序列

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-f8846702c19b`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

证据不足。若后续代码确实以可预测值（时间戳、自增整数）生成 dvwaSession 并作为认证凭据，则可导致会话预测/会话固定，进而劫持其他用户会话、绕过认证。但当前片段仅显示 last_session_id 初始化为 0，无法证明存在会话劫持或越权影响。

**CVE / CWE 论证**

CWE-330（Use of Insufficiently Random Values）/ CWE-340（Predictable Seed）。外部可达性：047.php 通过 POST 可达，无需认证即可触发该分支。但利用链未闭合：缺少会话 ID 生成算法、缺少 Cookie 写入点、缺少服务端接受该 ID 的校验逻辑，无法证明攻击者可预测并冒用有效会话。因此不满足 CVE 论证所需的「外部可达 + 无需认证 + 利用链闭合」三要素，当前仅为规则命中的语义模式（confidence 0.4）。

**修复建议**

1) 会话标识必须由密码学安全随机源生成（PHP 使用 session_start() 默认的 CSPRNG，或 random_bytes(32) 后 bin2hex）；禁止使用 time()、mt_rand()、自增整数或用户可控值作为 session id。2) 登录成功后调用 session_regenerate_id(true) 防会话固定。3) Cookie 设置 HttpOnly、Secure、SameSite=Lax/Strict。4) 若 last_session_id 仅用于业务计数，应改名以避免与会话标识混淆，并明确其非安全用途。5) 补充会话 ID 生成与校验代码后再复核该候选。

**验证说明**

静态证据：入口 POST /047；source=session/dvwaSession；sink=047.php:6；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 047.php 发送 POST 请求（第 5 行进入分支）→ 第 6 行判断 $_SESSION['last_session_id'] 未设置 → 第 7 行置为 0。片段到此为止，未出现会话 ID 生成、Cookie 下发或服务端接受逻辑，攻击者无法据此预测或伪造有效会话标识。利用链在 code_pack 范围内不闭合，需补充会话生成/校验代码才能确认。
AWVS 外部佐证：Predictable Session Identifier @ http://127.0.0.1:18081/047.php（未在本管线执行扫描）。

**外部佐证**

- awvs: Predictable Session Identifier @ http://127.0.0.1:18081/047.php

## 4. 二次注入（SecondOrderAnalyzer）

本次未发现 store→read→sink 闭环的二次注入链。

## 5. AWVS 联动

- 输入模式：`zip`
- 导入结果：1 条
- 关联明细：1 条
- 目标种子：`awvs/targets.json`
- 说明：AWVS 是外部动态扫描器；本管线只导入其结果做佐证，或导出端点供 AWVS 播种。

| finding | AWVS | URL | 结论 |
|---|---|---|---|
| `SEM-f8846702c19b` | Predictable Session Identifier | http://127.0.0.1:18081/047.php | corroborated |

## 6. 漏洞类型覆盖

| 类型 | CWE | AutoCVE | 本次数量 |
|---|---|---|---|
| `command_injection` | CWE-78 | 是 | 0 |
| `sql_injection` | CWE-89 | 是 | 0 |
| `blind_sql_injection` | CWE-89 |  | 0 |
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
| `open_redirect` | CWE-601 |  | 0 |
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
| `weak_id` | CWE-330 |  | 1 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.72 | 是 |
| surface_mapper | 攻击面测绘 | 7.22 | 是 |
| deep_finder | LLM 深挖 | 4.34 | 是 |
| candidate_screener | 候选筛选 | 4.13 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.11 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.5 | 否 |
| coordinator | 管线协调 | 6.02 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
