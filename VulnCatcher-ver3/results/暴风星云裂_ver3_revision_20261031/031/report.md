# 落日二号乙漏洞挖掘报告 — 20261031-011927-c1db88

- 生成时间：2026-10-30T17:19:59.246407+00:00
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

本次汇总仅含 1 条已去重 finding：SEM-27b732a5104d，类型 client_side_validation（CWE-602），严重度 high，位于 031.php 第 2 行，判定来源为规则（origin=rule），已附带 POC（has_poc=true）。最高危项即该条：脚本仅依赖外部 JavaScript 做客户端校验，服务端缺少对应校验，属可被绕过的高危实现缺陷。POC 齐全度：1/1 条 finding 有 POC，但需注意该 POC 为静态证据型（源码级），本次未做任何动态验证，不能宣称可动态复现。整体攻击面极小：仓库仅 031.php 一个 PHP 文件（3 行、129 字节），无框架、无端点清单、无隔离文件；且输入未提供该文件源码正文，因此除该条规则命中外，其余注入/文件操作/命令执行/反序列化/加密哈希类判断均缺乏代码证据，未做结论。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 166 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计了 code_pack 中唯一文件 031.php（3 行）。该文件是 DVWA 的 JavaScript 漏洞模块 high 级别片段：第 2 行将常量 DVWA_WEB_PAGE_TO_ROOT 与固定字符串 'vulnerabilities/javascript/source/high.js' 拼接后追加到 $page['body']，用于输出一个 <script> 标签。文件中不存在任何超全局变量读取（$_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER）、无文件/命令/反序列化/模板/数据库 sink、无哈希/加密/随机数/Cookie 标志位逻辑，也无认证或信任边界判断。DVWA_WEB_PAGE_TO_ROOT 为服务端常量，非攻击者可控，因此不构成 XSS 或路径注入；该片段本身不闭合任何 source→sink 链。surface_notes 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 候选在可见代码中均无对应实现证据，故不单独立项。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- code_pack 仅含 031.php 的 3 行片段，DVWA_WEB_PAGE_TO_ROOT 的定义、high.js 的实际内容、包含该片段的父页面与路由均不在包内，无法评估 high.js 客户端校验绕过等下游逻辑
- 无部署配置（php.ini/.htaccess/nginx.conf）、无 composer 依赖清单，无法评估配置型与组件级风险
- 无端点枚举与认证/会话配置证据，insecure_cookie 与 trust_boundary 无法确认

## 3. Findings

### F-1: 031.php 仅通过外部 JavaScript 做客户端校验（CWE-602）

- **类型**：`client_side_validation` / CWE-602
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`031.php:1-2`
- **来源**：`rule`

**描述**

证据仅覆盖 031.php 第 1-2 行：第 2 行通过 `$page['body'] .= '<script src="' . DVWA_WEB_PAGE_TO_ROOT . 'vulnerabilities/javascript/source/high.js"></script>'` 把外部脚本 high.js 引入页面。该片段本身只表明页面加载了客户端脚本，未包含任何表单字段、参数读取（如 $_GET/$_POST）、服务端校验逻辑或危险汇点。因此无法确认攻击者输入点、经过的变量/函数、校验为何无效，也无法确认最终到达的危险操作。候选 exploit_chain 中「客户端脚本参与校验；需同时审计服务端是否重复校验」属于规则语义命中，未给出具体服务端代码证据。

**source / sink**

- source：client `external JavaScript`（031.php）
- sink：031.php:2 $page[ 'body' ] .= '<script src="' . DVWA_WEB_PAGE_TO_ROOT . 'vulnerabilities/javascript/source/high.js"></script>';

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `031.php:2` | 客户端脚本参与校验；需同时审计服务端是否重复校验 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /031（ANY）的 客户端校验绕过 POC。注入点：ANY 参数 external JavaScript；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/031'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 客户端校验绕过 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/031?external JavaScript=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-27b732a5104d`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

证据不足。若服务端确实完全依赖 high.js 的客户端校验而缺少服务端重复校验，则攻击者可绕过前端限制提交任意值，导致业务规则绕过（如越权提交、数据完整性破坏）；但当前片段无法证明该影响成立。

**CVE / CWE 论证**

CWE-602（Client-Side Enforcement of Server-Side Security）要求证明安全决策在客户端执行且服务端未复验。输入仅提供 031.php:1-2 的脚本引入语句，缺少服务端处理代码与参数流，外部可达性、无需认证、利用链闭合均无法论证。

**修复建议**

在服务端对同一业务规则做独立、权威的校验：对所有来自客户端的参数在服务端重新验证类型、范围与权限；客户端脚本仅作为体验优化，不得作为安全边界。若 high.js 中定义了校验规则，应在服务端以等价逻辑复现，并对失败请求返回明确错误。

**验证说明**

静态证据：入口 ANY /031；source=client/external JavaScript；sink=031.php:2；规则 php-client-validation。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：当前可见链路仅为：页面渲染时在 031.php:2 拼接 `<script src=...high.js>` 引入客户端脚本。攻击者输入点、服务端接收变量、校验失效点与危险汇点均未在给定片段中出现，链路不闭合。

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
| safety_guard | 安全防护 | 2.89 | 是 |
| surface_mapper | 攻击面测绘 | 5.4 | 是 |
| deep_finder | LLM 深挖 | 3.12 | 是 |
| candidate_screener | 候选筛选 | 2.64 | 是 |
| vulnerability_analyzer | 漏洞分析 | 4.52 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.33 | 否 |
| coordinator | 管线协调 | 6.36 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
