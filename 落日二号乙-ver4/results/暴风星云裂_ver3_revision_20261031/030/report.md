# 落日二号乙漏洞挖掘报告 — 20261031-011913-2996a1

- 生成时间：2026-10-30T17:19:45.115728+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\030.zip`
- 输入模式：`zip`
- SHA256：`48d4b3a99200d915a9607662d8cd6ecde38870f14e54fee1fcb0210945f67000`
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

本次汇总仅含 1 条已去重 finding：LLM-49f2aa772ae4，类型 path_traversal，严重度 high，位于单文件 PHP 脚本 030.php（第 8 行附近），描述为 `page` 参数经不完整黑名单过滤后导致本地文件包含/路径穿越，且已附带 POC（has_poc=true）。这是本次唯一且最高危的发现，属静态源码推断（llm_finding），POC 为文本工件，未做动态验证。整体覆盖面极窄：仅 1 个文件、1 种语言（php）、0 个端点、无框架，攻击面测绘明确说明输入未提供 030.php 源码正文，因此除该条 finding 外无法形成其他结论。POC 齐全度为 1/1（仅就已有 finding 而言），但缺少 HTTP 层可复现证据链与端点/参数确认。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 296 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 030.php（10 行）。已审计其唯一外部输入点：第 4 行 `$_GET['page']` 读取到 `$file`，第 7-8 行使用 str_replace 做非递归黑名单过滤（http://、https://、../、..\），可被 `....//` 与嵌套协议串绕过。脚本注释表明 $file 用于“页面展示/包含”，但实际汇点调用位于第 10 行 `?>` 之后，未在可见范围内，因此路径穿越/文件包含链的最后一跳需人工确认。未发现 SQL、命令执行、反序列化、SSRF、弱加密等其他攻击面证据。输入中 surface_notes 的 risk_notes 属分析性描述而非代码事实，未作为结论依据。

未覆盖 / 证据缺口：
- 030.php 第 10 行之后的汇点调用（include/require/readfile 等）未在 CODE PACK 中，无法确认最终危险操作类型
- 无 php.ini / Web 服务器配置，无法确认 allow_url_include、open_basedir 等利用条件
- 无端点清单与部署信息，无法确认认证前置条件与网络可达性

## 3. Findings

### F-1: 030.php 中 `page` 参数经不完整黑名单过滤后导致本地文件包含/路径穿越

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`030.php:4-8`
- **来源**：`llm_finding`

**描述**

030.php 第 4 行直接读取 `$_GET['page']` 到 `$file`，第 7-8 行仅用 `str_replace` 删除 `http://`、`https://`、`../`、`..\` 子串作为“输入校验”。该过滤是非递归的一次性替换，可被绕过：`....//` 删除中间的 `../` 后重新拼成 `../`；`....\/` 同理。过滤后 `$file` 未做白名单、未做 realpath 规范化、未限制目录，直接作为页面包含/读取目标（脚本注释“The page we wish to display”表明其用途为包含/展示文件）。攻击者可通过路径穿越读取或包含任意本地文件，若 PHP 配置 allow_url_include 开启且过滤可绕过协议限制（如 `hthttp://tp://` 变形），还可导致远程文件包含进而 RCE。

**source / sink**

- source：query `page`（030.php:4）
- sink：030.php:8 过滤后的 $file 被用作页面包含/文件读取目标（脚本用途为“The page we wish to display”，第 10 行后应存在 include/require 或 readfile 类调用；CODE PACK 仅显示到第 10 行 `?>`，实际汇点调用未在可见范围内）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `030.php:4` | 从 GET 参数 page 读取攻击者可控字符串到 $file | 原始攻击者输入，未过滤 |  |
| 2 | `030.php:7` | str_replace 删除 http:// 与 https:// 子串 | 协议前缀被移除，但可通过嵌套变形（如 hthttp://tp://）绕过 | 单次非递归替换，嵌套协议串删除内层后重新拼出 http:// |
| 3 | `030.php:8` | str_replace 删除 ../ 与 ..\ 子串 | 路径穿越序列被移除，但 ....// 删除中间 ../ 后重新拼成 ../ | 单次非递归替换，....// → ../；....\/ → ..\ |
| 4 | `030.php:10` | 过滤后的 $file 作为页面包含/读取目标（汇点调用在可见行之外，需人工确认 include/require/readfile） | 穿越后的路径，指向任意本地文件 |  |

**POC**

针对 /030.php（GET）的路径穿越 / 任意文件读取 POC。注入点为 GET 参数 page，源码 030.php:8 将该参数直接拼入文件路径，未做规范化或白名单校验，攻击者可用 ../ 序列跳出预期目录读取任意文件。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/030.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 路径穿越 / 任意文件读写 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/030.php?page=..%2F..%2F..%2F..%2Ftmp%2Fsunset_LLM49f2a.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_LLM49f2a.txt`
- POC 目录：`poc/LLM-49f2aa772ae4`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

任意本地文件读取（源码、配置、凭据泄露）；若 allow_url_include 开启则可远程文件包含导致远程代码执行。

**CVE / CWE 论证**

CWE-22 路径穿越 / CWE-98 文件包含。外部 GET 参数直达文件操作汇点，过滤为可绕过的单次黑名单替换，无需认证，链闭合（汇点调用需人工确认在可见行之外）。

**修复建议**

使用白名单映射允许的页面名；对路径使用 realpath 规范化并校验前缀在允许目录内；禁止用户输入直接进入 include/require；关闭 allow_url_include。

**验证说明**

CODE PACK 仅显示 1-10 行，第 10 行 `?>` 之后使用 $file 的实际汇点调用（include/require/readfile）未在可见范围内，需人工确认汇点存在及类型；需确认 allow_url_include 配置以判断是否可升级为 RCE。
模型 POC 要点：利用 ....// 绕过 ../ 过滤，实现路径穿越读取/包含任意本地文件
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /030.php）：符合 CWE-22（路径穿越）。漏洞位于可交付代码 030.php:8，外部输入来自 query 参数 page，source→sink 链在给定代码范围内静态闭合，未发现有效净化（无 basename、realpath 前缀校验或白名单）。具备远程触发条件，无需认证（以源码可见范围为准）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行时请将 TARGET 替换为授权测试目标，并手动逐条发送请求。示例文件 /tmp/sunset_LLM49f2a.txt 仅为占位，实际测试应替换为目标上已知存在的可读文件（如 /etc/passwd 或应用配置文件），避免使用破坏性路径。禁止用于未授权系统。

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
| `path_traversal` | CWE-22 | 是 | 1 |
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
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.28 | 是 |
| surface_mapper | 攻击面测绘 | 5.13 | 是 |
| deep_finder | LLM 深挖 | 8.48 | 是 |
| candidate_screener | 候选筛选 | 3.47 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.65 | 是 |
| coordinator | 管线协调 | 6.12 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
