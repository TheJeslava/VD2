# 落日二号乙漏洞挖掘报告 — 20261031-215024-c1ef62

- 生成时间：2026-10-31T13:51:04.941439+00:00
- 输入：`$WORKSPACE\暴风星云裂\051.zip`
- 输入模式：`zip`
- SHA256：`96483940cd4d3e7d3eebe8443bc19f27aedea70513cee1c5302276aeb59557a9`
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

本次汇总 2 条已去重 findings：一条来自 AWVS 的 XSS（high，AWVS-3b651ba72b42，无文件/行号定位，仅有外部扫描证据），一条规则产出的 051.php 开放重定向候选（medium，GEN-6e4cfba5fa5e，第 9 行，证据自评为不足）。两条均带 POC，但性质不同：AWVS 条目属外部扫描证据，未在本次 code_pack 中定位到具体源码行，不能视为已由源码审计确认；开放重定向条目为静态规则推断，POC 为静态文本，未做动态验证。最高危为 AWVS 的 XSS（high）。整体覆盖面极窄：仅 1 个 PHP 文件、0 个端点、无框架，且输入未提供 051.php 源码正文，因此多数注入类判断缺乏证据，不能下结论。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 383 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 051.php（共 14 行，已完整展示 1-14 行）。该脚本仅做两件事：第 4-5 行从 $_GET['default'] 读取外部输入到 $default；第 8-11 行用 stripos($default, "<script") 做黑名单检查，命中则 302 跳转到 ?default=English 并 exit。第 12-14 行之后没有任何输出、拼接、文件操作、命令执行、SQL、include/require 或其它 sink——$default 在通过检查后既未被 echo/print 输出，也未被传入任何危险函数，数据流在赋值后即终止。因此不存在可闭合的 source→sink 利用链：既无反射型 XSS（无输出点），也无 LFI/路径穿越/命令注入/SQL 注入（无对应汇点）。surface_notes 中提到的“第 3 行 source 热点”与实际代码不符（第 3 行是注释，真实输入在第 4-5 行），且 sink_hot_files 为空与代码事实一致。按“宁可漏报不可误报”原则，不产出 finding。未闭合线索：若该片段在真实部署中被其它文件 include 并在后续使用 $default，则可能存在 XSS 或其它注入，但该上下文不在 code_pack 内，无法评估。

未覆盖 / 证据缺口：
- code_pack 仅含 051.php 一个文件，无路由/部署/包含关系信息，无法确认 $default 是否在别处被使用
- 无 composer.json、Web 服务器配置、PHP 版本信息，无法评估 allow_url_include 等运行时条件
- endpoints 为空，无法确认脚本的 HTTP 可达路径与方法

## 3. Findings

### F-1: AWVS: Cross-site Scripting (XSS)

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `external_only`
- **位置**：外部扫描端点 `/051.php`
- **来源**：`awvs`

**描述**

Local AWVS-compatible probe observed unsafe DOM sink. baseline HTTP 200 (5092 bytes); attack HTTP 200 (5092 bytes); marker='DOM source/sink'.

**source / sink**

- source：外部扫描目标 http://127.0.0.1:18081/051.php
- sink：AWVS 报告端点

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `http://127.0.0.1:18081/051.php` | AWVS 报告 Cross-site Scripting (XSS) |  |  |

**POC**

AWVS 外部扫描在 http://127.0.0.1:18081/051.php 报告 XSS（CWE-79），标记为 DOM source/sink。本管线未执行验证，仅保留 AWVS 记录的请求结构并补充复现说明；源码文件与行号未在输入中提供，具体注入参数需补充源码/路由确认。

1. **重放 AWVS 记录的请求**

```http
GET /051.php HTTP/1.1
Host: TARGET


```
预期：复现 AWVS 报告中的问题

- POC 目录：`poc/AWVS-3b651ba72b42`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

Local AWVS-compatible probe observed unsafe DOM sink. baseline HTTP 200 (5092 bytes); attack HTTP 200 (5092 bytes); marker='DOM source/sink'.

**CVE / CWE 论证**

AWVS 外部报告；CWE-79；未在本管线内动态验证。

**修复建议**

按 AWVS 报告复现并修复；补充源码定位与参数化/白名单。

**验证说明**

来源：AWVS 报告回灌。无源码证据，需人工定位。
POC 备注：仅文本工件，不执行、不联网。AWVS 原始 URL 中的 127.0.0.1:18081 已替换为 TARGET。因缺少源码文件与行号，未给出具体注入参数，需补充源码/路由后再定稿 payload。

### F-2: 051.php 开放重定向候选（CWE-601）证据不足

- **类型**：`open_redirect` / CWE-601
- **严重度**：`medium`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`051.php:7-9`
- **来源**：`rule`

**描述**

候选声称 051.php:5 从 query 参数 `default` 读取外部输入，并在 051.php:9 通过 header("location: ?default=English") 形成开放重定向。但输入给出的代码片段仅包含第 7-9 行：第 7 行为注释 `# Do not allow script tags`，第 8 行为 `if (stripos ($default, "<script") !== false) {`，第 9 行为 `header ("location: ?default=English");`。第 5 行的 `$default` 赋值语句未出现在 code_pack 片段中，无法确认其来源是 `$_GET['default']`、`$_REQUEST` 还是其他变量；也无法确认是否存在其他拼接或重定向逻辑。此外，第 9 行的 Location 值是固定字符串 `?default=English`，不含 `$default` 变量，因此该行本身不构成把用户输入写入 Location 头的重定向汇点。

**source / sink**

- source：query `default`（051.php:5）
- sink：051.php:9 header ("location: ?default=English");

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `051.php:5` | 从 query `default` 读取外部输入 | 污点进入 default |  |
| 2 | `051.php:9` | 危险汇点：header ("location: ?default=English"); | 污点进入 open_redirect 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /051（GET）的 开放重定向 POC。注入点：GET 参数 default；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/051'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 开放重定向 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/051?default=%2F%2Fexample.com'
```
预期：响应为 30x 且 Location 指向攻击者控制的域名。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`//example.com`
- POC 目录：`poc/GEN-6e4cfba5fa5e`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

证据不足，无法确认可利用影响。若第 5 行确实将 `$_GET['default']` 直接用于 Location 头，则可能被用于钓鱼跳转（将用户导向攻击者站点）；但当前片段中第 9 行 Location 为常量，未体现该链路。

**CVE / CWE 论证**

CWE-601（URL 重定向至不可信站点）要求外部可控输入进入 Location/Refresh 等跳转目标。当前证据仅显示第 8 行对 `$default` 做 `<script` 子串检查（stripos），该检查与重定向目标无关且可被绕过（如大小写、编码），但缺少第 5 行 source 赋值与真正的跳转汇点，外部可达性与利用链未闭合，不能据此认定 CVE。

**修复建议**

若确认存在跳转逻辑：不要将用户输入直接拼入 Location 头；改用服务端白名单映射（如允许的页面键到固定 URL 的映射表），或对目标做规范化后校验 scheme/host 必须属于本站允许列表，拒绝 `//`、`http:`、`https:` 等外部前缀；同时保留对响应头的 CRLF 过滤。若第 9 行确为固定值，则应删除该候选或补充第 5 行源码证据。

**验证说明**

静态证据：入口 GET /051；source=query/default；sink=051.php:9；规则 php-redirect。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：候选链路为：051.php:5 读取 query `default` → 051.php:8 仅检查是否含 `<script` → 051.php:9 header("location: ?default=English")。缺口在于：(1) 第 5 行赋值语句不在 code_pack 中，source 未证实；(2) 第 9 行 Location 值为常量，未包含 `$default`，sink 未证实。因此链路不闭合，仅能作为待补证的候选。
PocWriter 建议（未采纳，缺少端点 /051）：针对 051.php 第 9 行开放重定向（CWE-601）的文本 POC。源码将 GET 参数 default 的值直接用于重定向目标，未做白名单/同源校验，攻击者可用 //example.com 之类的协议相对 URL 把用户跳转到外部站点。
PocWriter 建议（未采纳，缺少端点 /051）：符合 CWE-601（URL 重定向到不可信站点）。漏洞位于 051.php:9，外部输入来自 GET 参数 default，source→sink 链静态闭合，未见有效净化，可远程触发。
POC 备注：仅文本工件，不执行、不联网。目标地址统一使用 TARGET:8080；实际测试需替换为授权目标。检查响应头 Location 而非响应体。

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
| `AWVS-3b651ba72b42` | Cross-site Scripting (XSS) | http://127.0.0.1:18081/051.php | external_only |

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
| `xss` | CWE-79 | 是 | 1 |
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
| safety_guard | 安全防护 | 3.74 | 是 |
| surface_mapper | 攻击面测绘 | 7.19 | 是 |
| deep_finder | LLM 深挖 | 4.32 | 是 |
| candidate_screener | 候选筛选 | 3.14 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.67 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.52 | 是 |
| coordinator | 管线协调 | 7.19 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
