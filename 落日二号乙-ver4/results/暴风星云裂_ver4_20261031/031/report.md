# 落日二号乙漏洞挖掘报告 — 20261031-164434-a21302

- 生成时间：2026-10-31T08:45:14.168548+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\031.zip`
- 输入模式：`zip`
- SHA256：`b0fc9cc03119c44c0eb5f634603a0bfdc94bdb3472f96b4db80ea87e95d9a867`
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

本次汇总仅含 1 条已去重 finding：SEM-27b732a5104d，类型 client_side_validation（CWE-602，high），位于 031.php 第 1-2 行，页面仅通过外部 JavaScript 引入校验逻辑，属规则命中且已附 POC（静态/HTTP 文本 POC，未执行）。最高危即此条 high。POC 齐全度：1/1 有 POC，但均为文本工件，未经动态验证。整体攻击面极小（单文件 PHP、3 行、129 字节、无框架、无端点清单），且本次未提供 031.php 正文，行级审计证据有限，结论以规则命中与元数据为准。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 166 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 031.php 一个文件，共 3 行（1-3 行全部可见，未截断）。逐行审计结果：第 1 行为 PHP 开标签；第 2 行将一段静态字符串（引用 DVWA_WEB_PAGE_TO_ROOT 常量拼接的固定 JS 路径）追加到 $page['body']；第 3 行为闭标签。该文件不接收任何外部输入（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER 读取），无 include/require、无 eval/assert/system/exec/shell_exec/passthru/proc_open、无文件读写、无 SQL、无 header 跳转、无 setcookie/session 配置、无 md5/sha1/rand/mt_rand 等弱算法调用，也无硬编码凭据。唯一的外部符号 DVWA_WEB_PAGE_TO_ROOT 是常量，其值不在 code_pack 内，但即使被污染也只能影响静态 script 标签的 src 前缀，且该常量通常由服务端配置定义，不构成攻击者可控的 source→sink 链。因此不存在可闭合的 CVE 级利用链，findings 为空。未闭合线索：DVWA_WEB_PAGE_TO_ROOT 的定义位置与取值不在 code_pack 中，无法确认其是否可被外部影响；该文件所属的 DVWA 框架其余文件（如 JS 漏洞模块的 high.js、路由与配置）未送入本次 code_pack，按契约视为不存在，未做审计。surface_notes 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary/hardcoded_secret 六类候选，经逐行核对在本文件中均无对应代码证据，属未证实线索而非漏洞。

未覆盖 / 证据缺口：
- DVWA_WEB_PAGE_TO_ROOT 常量定义与赋值不在 code_pack，无法评估其可控性
- DVWA 框架其余文件（路由、配置、vulnerabilities/javascript/source/high.js 等）未送入 code_pack，未审计
- 无部署配置（nginx/apache/php.ini），无法确认该脚本对外可达性与危险函数禁用状态
- 无端点清单与请求样例，无法确认实际调用方式

## 3. Findings

### F-1: 031 客户端校验绕过（CWE-602）：页面仅通过外部 JavaScript 引入校验逻辑

- **类型**：`client_side_validation` / CWE-602
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`031.php:1-2`
- **来源**：`rule`

**描述**

证据来自 031.php 第 1-2 行：第 2 行通过字符串拼接把外部脚本 `vulnerabilities/javascript/source/high.js` 以 `<script src=...>` 形式注入到 `$page['body']` 中，页面本身（第 1-3 行）不含任何 PHP 侧校验代码。也就是说，该页面把校验职责完全交给浏览器端脚本，服务端在本次可见代码范围内没有对应的重复校验。攻击者输入点位于客户端：攻击者可直接读取 high.js 中的校验规则，绕过或禁用该脚本（例如用代理拦截、浏览器控制台改写、或直接构造请求跳过页面），从而提交本应被脚本拦截的数据。由于输入中未提供 high.js 内容与任何服务端接收/处理端点，无法确认被校验的具体参数名、提交目标路由以及绕过后的危险汇点，因此“校验无效”的具体机制与最终危险操作属于证据不足，仅能确认“校验逻辑位于客户端、服务端未见重复校验”这一结构性事实。

**source / sink**

- source：client `external JavaScript`（031.php）
- sink：031.php:2 $page[ 'body' ] .= '<script src="' . DVWA_WEB_PAGE_TO_ROOT . 'vulnerabilities/javascript/source/high.js"></script>';

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `031.php:2` | 客户端脚本参与校验；需同时审计服务端是否重复校验 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /031（ANY）的 客户端校验绕过 POC。注入点：ANY 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/031'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 客户端校验绕过 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/031?include=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-27b732a5104d`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

若该页面所保护的业务操作（如提交表单、修改数据）确实只依赖 high.js 做校验，则攻击者可绕过全部客户端约束，向服务端提交任意构造的数据，可能导致业务规则被绕过、非法数据写入或越权操作。具体影响面（是否可写入数据库、是否可越权修改他人数据）因缺少服务端处理代码而证据不足，不能断言 RCE 或数据泄露。

**CVE / CWE 论证**

CWE-602（Client-Side Enforcement of Server-Side Security）：安全决策被放在客户端执行，服务端未强制重复校验。外部可达性：该页面为 Web 可访问页面，无需认证即可加载（DVWA 环境通常需登录，但输入未给出认证要求，故认证条件证据不足）。利用链闭合度：仅闭合到“校验在客户端”这一环，缺少服务端接收点与危险汇点，链未完全闭合，故置信度维持较低水平。

**修复建议**

1) 在服务端对同一业务操作实施与 high.js 等价的强制校验，客户端脚本仅作为体验优化，不作为安全边界；2) 对所有入参做白名单/类型/长度校验，并在服务端统一返回错误；3) 避免把校验规则以可读脚本形式暴露为唯一防线；4) 对关键操作增加服务端会话与权限校验，防止绕过前端后直接调用接口。

**验证说明**

静态证据：入口 ANY /031；source=client/external JavaScript；sink=031.php:2；规则 php-client-validation。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者访问 031.php → 页面第 2 行加载 high.js 作为唯一校验 → 攻击者通过禁用脚本/拦截请求/直接构造 HTTP 请求跳过客户端校验 → 服务端（本次证据未提供）若未重复校验则接受被篡改数据。由于缺少服务端处理代码与具体参数名，链条在“服务端接收并处理”环节证据不足。

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
| `client_side_validation` | CWE-602 |  | 1 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.8 | 是 |
| surface_mapper | 攻击面测绘 | 7.4 | 是 |
| deep_finder | LLM 深挖 | 4.03 | 是 |
| candidate_screener | 候选筛选 | 3.56 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.46 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.06 | 否 |
| coordinator | 管线协调 | 6.1 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
