# 落日二号乙漏洞挖掘报告 — 20261031-173021-e4b3a1

- 生成时间：2026-10-31T09:30:56.733554+00:00
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

本次汇总仅含 1 条已去重 finding：SEM-27b732a5104d，类型 client_side_validation（CWE-602），严重度 high，位于 031.php 第 1-2 行，判定依据是该文件仅通过外部 JavaScript 引入客户端校验脚本，服务端未见对应校验。该条已附带 POC（静态/HTTP 文本工件，未执行、未动态验证）。最高危即此条 high。POC 齐全度为 1/1，但需注意：该 POC 属静态证据型，尚未经动态复现。整体可审计面极小（单文件 PHP，3 行 129 字节，无框架、无端点清单、无 source/sink 标注），注入类与配置类结论均缺乏行号级源码证据，不能据此宣称安全。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 166 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 031.php 的 3 行内容（第 1-3 行）：第 1 行为 <?php 起始标签，第 2 行将一段静态字符串（引用 DVWA_WEB_PAGE_TO_ROOT 常量拼接的 high.js 脚本标签）追加到 $page['body']，第 3 行为 ?> 结束标签。该文件不含任何外部输入读取（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER）、无 include/eval/assert/system/exec/shell_exec、无 SQL 查询、无文件读写、无 setcookie/session 配置、无 md5/sha1/rand/mt_rand 等弱算法调用。$page['body'] 的拼接内容完全由常量 DVWA_WEB_PAGE_TO_ROOT 与固定字面量构成，攻击者无法控制，因此不存在 source→sink 链路，无法构造任何注入类或配置类 finding。surface_notes 中关于“一句话/后门脚本”的推测属于基于文件体量的推断，与 code_pack 实际内容不符，不予采纳；其中列出的 Java 语义汇点（getParameterMap/Runtime.exec 等）在本 PHP 文件中均不存在。未闭合线索：DVWA_WEB_PAGE_TO_ROOT 常量的定义与赋值位置不在 code_pack 内（视为不存在），无法确认其是否可被外部影响；该文件在 DVWA 中属于 javascript 模块的页面片段，实际入口与包含它的父页面不在本次 code_pack 范围内。

未覆盖 / 证据缺口：
- DVWA_WEB_PAGE_TO_ROOT 常量定义文件未提供，无法评估其可控性
- 包含 031.php 的父页面/路由入口未提供，无法确认部署路径与认证要求
- 无 php.ini / Web 服务器配置，无法评估运行时设置
- 无框架与第三方依赖信息，无法评估组件 CVE

## 3. Findings

### F-1: 031.php 仅通过外部 JavaScript 引入客户端校验脚本（CWE-602 客户端校验依赖）

- **类型**：`client_side_validation` / CWE-602
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`031.php:1-2`
- **来源**：`rule`

**描述**

证据仅覆盖 031.php 第 1-2 行：第 2 行通过字符串拼接把 DVWA_WEB_PAGE_TO_ROOT . 'vulnerabilities/javascript/source/high.js' 作为 <script src> 输出到 $page['body']，即页面把校验逻辑完全交给浏览器端加载的 high.js。攻击者输入点应为该页面表单提交的参数，但输入中未给出任何 getParameter/$_GET/$_POST 读取点，也未给出服务端校验或服务端处理代码；high.js 文件内容不在 code_pack 内，无法确认其校验逻辑，也无法确认服务端是否重复校验。因此“校验无效”这一环在现有证据下无法闭合：只能确认页面依赖客户端脚本，不能确认存在可绕过的服务端缺失校验。

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

若服务端确实未对同一参数重复校验（当前证据不足），攻击者可用代理/浏览器控制台跳过 high.js 校验直接提交任意值，导致业务规则绕过（如越权提交、非法值落库）。在现有证据下无法确认具体影响面，证据不足。

**CVE / CWE 论证**

CWE-602（Client-Side Enforcement of Server-Side Security）：031.php:2 将校验实现放在外部 JS 中由客户端执行，属于典型客户端校验依赖模式；但外部可达性、无需认证、利用链闭合三项均无法从给定片段确认——缺少服务端接收参数与处理逻辑的代码，缺少 high.js 内容，故不满足完整 CVE 论证条件。

**修复建议**

在服务端对同一参数执行与 high.js 等价或更严格的校验（类型、范围、白名单），客户端脚本仅作为体验优化；对提交值做服务端规范化与白名单比对；不要以 JS 校验结果作为安全判定依据；对关键操作增加服务端会话/权限校验。

**验证说明**

静态证据：入口 ANY /031；source=client/external JavaScript；sink=031.php:2；规则 php-client-validation。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：031.php:2 输出 <script src=.../high.js>，浏览器加载并执行 high.js 中的校验；攻击者可在本地禁用/修改该脚本或直接构造请求绕过。但输入未提供服务端参数读取点（source）与服务端处理/落库点（sink），high.js 内容亦不可见，故从“客户端校验”到“服务端缺失校验被利用”的链条在证据上断开，仅能确认客户端校验依赖这一事实。
PocWriter 建议（未采纳，缺少端点 /031）：针对 031.php:2 的客户端校验绕过（CWE-602）POC 文本。源码中外部输入来自查询参数 include，但当前证据未给出该参数在服务端的具体汇点与净化逻辑，也未确认 HTTP 方法，因此本 POC 仅保留确定性草稿的请求结构，并标注需补充的源码/路由信息，不伪造字段。
PocWriter 建议（未采纳，缺少端点 /031）：对应 CWE-602（客户端安全校验依赖）。证据等级：llm_inferred。漏洞位置 031.php:2，外部输入来自查询参数 include，但 source→sink 链在给定证据中未完整闭合（汇点与净化逻辑缺失），因此结论为基于源码位置的推断，非已验证事实。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。草稿中的 ANY 方法与 curl 命令仅作结构参考，实际方法需按 031.php:2 源码确认后改为 GET 或 POST；禁止使用抽象占位符替代真实字段，字段名 include 来自草稿证据。

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
| safety_guard | 安全防护 | 4.06 | 是 |
| surface_mapper | 攻击面测绘 | 6.85 | 是 |
| deep_finder | LLM 深挖 | 4.02 | 是 |
| candidate_screener | 候选筛选 | 2.99 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.82 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.92 | 是 |
| coordinator | 管线协调 | 5.55 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
