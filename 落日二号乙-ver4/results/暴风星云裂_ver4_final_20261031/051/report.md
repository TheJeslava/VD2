# 落日二号乙漏洞挖掘报告 — 20261031-173348-85f61d

- 生成时间：2026-10-31T09:34:27.095457+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\051.zip`
- 输入模式：`zip`
- SHA256：`96483940cd4d3e7d3eebe8443bc19f27aedea70513cee1c5302276aeb59557a9`
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

本次汇总仅含 1 条去重后的 finding：051.php 的开放重定向候选（open_redirect，CWE-601，medium，GEN-6e4cfba5fa5e），来源为规则命中，已附带 POC 文本（静态/HTTP 未区分，需按 POC 内容确认）。该候选自身标注“证据不足以确认可利用”，因此最高危项也仅为 medium 且可利用性未定。整体攻击面极小：code_pack 仅含 051.php（14 行、289 字节），无框架、无路由、无端点清单，sink 热点为空。POC 覆盖率为 1/1（有 POC 的 finding 数等于 finding 总数），但仅此一条，且无二次注入链、无外部 AWVS 证据。结论：本次交付物为 1 条 medium 开放重定向候选 + 1 份 POC 文本，未做任何动态验证。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 383 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 051.php（14 行）。已逐行审计：第 4 行通过 array_key_exists("default", $_GET) 读取外部参数 default，第 5 行赋值给 $default，第 8 行用 stripos($default, "<script") 做黑名单校验，命中则第 9 行 header("location: ?default=English") 重定向并 exit。关键事实：$default 在整份代码中除第 8 行的 stripos 校验外没有任何其它使用点——没有 echo/print/printf 输出，没有 include/require/file_get_contents/fopen 等文件操作，没有 system/exec/shell_exec/passthru/proc_open/popen 等命令执行，没有 eval/assert/create_function/preg_replace /e，没有 SQL 调用，没有 setcookie/session_set_cookie_params，没有 md5/sha1/rand/mt_rand/openssl_encrypt 等密码学调用。因此 source（$_GET['default']）到任何危险 sink 的数据流均不闭合：既无反射型 XSS 的输出汇点，也无路径穿越/LFI/命令注入/代码注入的汇点。第 8 行的 stripos 黑名单本身可被绕过（如大小写混合、<img onerror> 等非 script 标签），但由于不存在任何输出或执行汇点，绕过它不产生可利用影响，不构成可申报漏洞。surface_notes 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 候选经核对均无对应代码证据，属规则未命中而非真实缺陷。未闭合线索：无法确认 051.php 是否被其它未提供的文件 include 并在别处输出 $default（code_pack 之外文件视为不存在，不做假设）；无 php.ini/路由/部署信息，无法评估运行环境相关可利用性。按“宁可漏报不可误报”原则，不输出 finding。

未覆盖 / 证据缺口：
- 051.php 之外的文件（配置、路由、被 include 的父页面）未提供，若 $default 在别处被输出则可能构成 XSS，但当前证据不支持
- 无 php.ini / Web 服务器配置，无法确认 allow_url_include、open_basedir、display_errors 等
- 无端点清单，无法确认 051.php 是否直接对外暴露
- 无数据库/模板/日志依赖，SQL 注入与二次注入无法评估
- 无认证/会话文件，insecure_cookie 与 trust_boundary 缺乏证据

## 3. Findings

### F-1: 051.php 开放重定向候选（CWE-601）——证据不足以确认可利用

- **类型**：`open_redirect` / CWE-601
- **严重度**：`medium`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`051.php:7-9`
- **来源**：`rule`

**描述**

候选声称 051.php:5 从 query 参数 `default` 读取外部输入，并在 051.php:9 的 header("location: ?default=English") 处形成开放重定向。但按输入给出的代码片段，第 8 行是 `if (stripos ($default, "<script") !== false)`，第 9 行是 `header ("location: ?default=English");`——该 header 的 Location 值是硬编码字符串 `?default=English`，其中不含变量 `$default`，因此外部输入并未到达该 header 汇点。片段中也没有出现把 `$default` 拼入 Location 的语句（例如 header("Location: ".$default)）。所以 source→sink 的污点链在给定证据下不闭合：第 9 行只是对含 `<script` 的输入做固定回退跳转，属于黑名单式过滤，而非把用户输入写入跳转目标。攻击者输入点（query `default`）与危险操作（Location 头）之间缺少数据流证据。

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

证据不足，无法确认影响。若后续证据显示存在 header("Location: ".$default) 之类的拼接，则可能被用于钓鱼跳转（将用户导向攻击者站点）；但当前片段仅显示固定值跳转，不构成开放重定向。

**CVE / CWE 论证**

CWE-601（URL 重定向至不可信站点）要求攻击者可控数据进入 Location/Refresh 等跳转目标。输入片段中 051.php:9 的 Location 值为常量 `?default=English`，不含 `$default`，外部可达性与可控性均未得到证据支持；同时第 8 行仅用 stripos 黑名单检查 `<script`，即便存在拼接也属可绕过的弱校验，但该前提在给定代码中不成立。故不满足利用链闭合条件，不能作为已确认漏洞。

**修复建议**

若确认存在将 `$default` 拼入 Location 的代码，应改为白名单映射：仅允许预定义的语言/页面键（如 English、Chinese），映射到固定相对路径，禁止直接把用户输入作为跳转目标；对跳转目标做同源校验（解析后 host 必须为空或等于本站），拒绝 `//`、`http:`、`https:`、`\\` 等前缀；不要依赖 `<script` 黑名单。若当前代码确为固定跳转，建议关闭该候选或补充真实拼接行号后再评估。

**验证说明**

静态证据：入口 GET /051；source=query/default；sink=051.php:9；规则 php-redirect。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：候选链路：051.php:5 读取 query `default` → 051.php:8 stripos 检查 `<script` → 051.php:9 header("location: ?default=English")。核对片段后，第 9 行 Location 为硬编码常量，`$default` 未进入该 header，污点链在第二步即中断；第 8 行的黑名单检查针对的是 `<script`，与重定向目标无关。因此该候选在当前证据下不成立，置信度应下调。
PocWriter 建议（未采纳，缺少端点 /051）：针对 051.php 第 9 行开放重定向（CWE-601）的文本 POC。源码从 GET 参数 `default` 读取跳转目标并直接用于重定向响应，未做白名单或同源校验；payload 使用 `//example.com`（协议相对 URL），使浏览器跳转到外部域。目标地址统一使用 `TARGET` 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /051）：符合 CWE-601（URL 重定向到不可信站点）。漏洞位于可交付代码 051.php:9，外部输入来自查询参数 `default`，source→sink 链在给定代码范围内静态闭合，未发现白名单/同源校验等有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅保留文本请求结构，不生成可自动执行的脚本；如需手工复现，请自行在授权环境用浏览器或 HTTP 客户端发送上述请求，并重点检查响应头 `Location`。不要对非授权目标发送请求。

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
| safety_guard | 安全防护 | 4.11 | 是 |
| surface_mapper | 攻击面测绘 | 8.7 | 是 |
| deep_finder | LLM 深挖 | 3.95 | 是 |
| candidate_screener | 候选筛选 | 2.17 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.94 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.05 | 是 |
| coordinator | 管线协调 | 8.07 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
