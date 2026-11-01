# 落日二号乙漏洞挖掘报告 — 20261031-214625-81b4f6

- 生成时间：2026-10-31T13:47:05.359306+00:00
- 输入：`$WORKSPACE\暴风星云裂\031.zip`
- 输入模式：`zip`
- SHA256：`b0fc9cc03119c44c0eb5f634603a0bfdc94bdb3472f96b4db80ea87e95d9a867`
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

本次汇总仅含 1 条已去重 finding：SEM-27b732a5104d，类型 client_side_validation（CWE-602，客户端校验绕过），严重度 high，位于 031.php 第 2 行，来源为规则命中，已附带 POC（静态/HTTP 性质需按该规则语义复核，本次未做动态验证）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 有 POC，但均为文本工件，未执行、未搭建沙箱、未做动态验证。需特别说明：surface_notes 明确指出输入只给出文件清单而未给出 031.php 源码内容，因此该 finding 的行号与结论无法在本上下文中与源码逐行对齐，属于需人工回看源码确认的项。攻击面测绘提出的注入类、配置类风险点均未被任何 finding 覆盖，已转入 human_review。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 166 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含一个 3 行 PHP 文件 031.php（DVWA 的 javascript 漏洞模块 high 级别片段）。第 2 行将常量 DVWA_WEB_PAGE_TO_ROOT 与固定字符串 'vulnerabilities/javascript/source/high.js' 拼接后追加到 $page['body']，无任何外部请求输入（无 $_GET/$_POST/$_COOKIE/$_SERVER 读取），无 include/require、无 SQL、无命令执行、无文件读写、无 URL 请求、无输出到客户端的未转义用户数据。DVWA_WEB_PAGE_TO_ROOT 为框架内定义的常量，非攻击者可控，因此不存在 source→sink 污点链。文件中亦无 md5/sha1/rand/setcookie/openssl 等配置型风险调用，surface_notes 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 均无对应代码证据，属未闭合线索而非漏洞。未发现 prompt_injection 文本。按零容忍误报原则，不产出 finding。

未覆盖 / 证据缺口：
- code_pack 仅含 031.php 的 1-3 行，DVWA_WEB_PAGE_TO_ROOT 常量定义、high.js 内容、路由与认证逻辑均不在 code_pack 内，视为不存在，无法进一步追踪
- 无端点清单、无配置文件、无依赖清单，无法评估部署暴露面与第三方组件
- surface_notes 中列出的配置型候选（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）在可见代码中无对应调用，证据不足，未报告

## 3. Findings

### F-1: 031 客户端校验绕过（CWE-602）

- **类型**：`client_side_validation` / CWE-602
- **严重度**：`high`
- **置信度**：`0.43`
- **结论**：`candidate` / 证据等级 `externally_corroborated`
- **位置**：`031.php:1-2`
- **来源**：`rule`

**描述**

证据仅覆盖 031.php 第 1-2 行：第 2 行通过 `$page['body'] .= '<script src="' . DVWA_WEB_PAGE_TO_ROOT . 'vulnerabilities/javascript/source/high.js"></script>'` 把外部脚本 high.js 引入页面。该脚本属于客户端校验逻辑，攻击者可直接在浏览器中禁用/篡改 JS、用代理改包或直接调用后端接口，绕过 high.js 中的校验。但输入中未提供 high.js 内容，也未提供服务端处理该请求的 PHP 代码，因此无法确认服务端是否重复校验、具体被绕过的字段名与后端汇点。攻击者输入点、经过的变量与最终危险操作均证据不足。

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

若服务端确实仅依赖 high.js 做校验，攻击者可绕过前端限制提交本应被拒绝的数据（如越权修改、非法值写入），造成业务逻辑绕过。具体影响面（数据篡改/越权/写入）因缺少服务端代码证据不足，不能断言 RCE 或数据泄露。

**CVE / CWE 论证**

CWE-602（Client-Side Enforcement of Server-Side Security）：安全决策放在客户端脚本 high.js 中，客户端完全受攻击者控制，可被禁用或改写，因此不构成有效防护。外部可达性：页面 031.php 为 Web 入口，无需认证即可加载该脚本（DVWA 默认低安全级别下无需登录即可访问，具体认证要求证据不足）。利用链闭合性：输入点（客户端可控的请求/脚本执行环境）→ 绕过 high.js 校验 → 服务端接收未校验数据，但服务端汇点未在输入中给出，链条最后一环证据不足。

**修复建议**

1) 所有校验必须在服务端 PHP 中重新实现，客户端 JS 仅作体验优化，不得作为安全边界；2) 对提交字段使用白名单与类型/长度/范围校验，服务端拒绝非法值；3) 对涉及权限的操作在服务端做授权检查（会话用户与目标资源归属比对）；4) 增加服务端单元/集成测试覆盖绕过前端的直接请求场景。

**验证说明**

静态证据：入口 ANY /031；source=client/external JavaScript；sink=031.php:2；规则 php-client-validation。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：031.php:2 引入 vulnerabilities/javascript/source/high.js，校验逻辑运行在浏览器端。攻击者可通过禁用 JS、修改 high.js 或直接构造 HTTP 请求跳过该校验，将原本被前端拦截的数据提交到服务端。由于输入未包含服务端处理代码，无法确认服务端是否二次校验，也无法定位最终危险操作，故该链条在服务端汇点处证据不足。
AWVS 外部佐证：Client-side Validation Bypass @ http://127.0.0.1:18081/031.php（未在本管线执行扫描）。
PocWriter 建议（未采纳，缺少端点 /031）：针对 031.php 第 2 行的客户端校验绕过（CWE-602）候选。源码中该入口把外部输入 include 直接用于客户端侧逻辑，服务端未做等价校验，因此攻击者可以绕过前端限制直接提交任意 include 值。注意：输入给出的端点使用了 ANY 方法与抽象参数名，无法从 code_pack 确认真实 HTTP 方法、参数名与路由，需补充源码/路由后再定稿。
PocWriter 建议（未采纳，缺少端点 /031）：符合 CWE-602（Client-Side Enforcement of Server-Side Security）。证据位于 031.php:2，外部输入进入客户端校验路径而服务端无等价校验；当前为静态推断（llm_inferred），未做动态验证。
POC 备注：仅限授权测试。原草稿中的 ANY 方法与 include 参数名未经源码证实，定稿前必须按 031.php 实际读取的参数名与真实 HTTP 方法替换；不得直接执行脚本，POC 仅为文本工件。

**外部佐证**

- awvs: Client-side Validation Bypass @ http://127.0.0.1:18081/031.php

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
| `SEM-27b732a5104d` | Client-side Validation Bypass | http://127.0.0.1:18081/031.php | corroborated |

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
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 1 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 4.4 | 是 |
| surface_mapper | 攻击面测绘 | 7.73 | 是 |
| deep_finder | LLM 深挖 | 3.78 | 是 |
| candidate_screener | 候选筛选 | 3.74 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.43 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.33 | 是 |
| coordinator | 管线协调 | 8.76 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
