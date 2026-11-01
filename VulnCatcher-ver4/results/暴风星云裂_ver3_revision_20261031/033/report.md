# 落日二号乙漏洞挖掘报告 — 20261031-011946-abcda4

- 生成时间：2026-10-30T17:20:18.313221+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\033.zip`
- 输入模式：`zip`
- SHA256：`2cc6995b797e45b354fcf30552f7b1dba5f3ce341ebf99c3f25eb6325b4dee16`
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

本次汇总仅含 1 条已去重 finding：SEM-2ffadbadfdc4，类型 client_side_validation（CWE-602，客户端校验绕过），严重度 high，位于 033.php 第 2 行，来源为规则命中，已附带 POC（1/1 齐全）。最高危即该条 high 级客户端校验绕过；其 POC 属静态/HTTP 待定性质，本次未做任何动态验证，不能宣称可动态复现。整体覆盖极薄：仅 1 个文件、1 种语言（php）、0 个端点、无框架，攻击面测绘明确说明未拿到 033.php 正文，因此注入、路径穿越、命令执行等高价值面均未做行级审计，结论仅为保守推断。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 168 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单文件 033.php（3 行，131 字节），已完整审计第 1-3 行。代码内容为：第 1 行 PHP 起始标签；第 2 行将一段静态字符串（引用 DVWA_WEB_PAGE_TO_ROOT 常量拼接固定路径 vulnerabilities/javascript/source/medium.js）追加到 $page['body']；第 3 行结束标签。该文件不含任何外部输入接收（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER 取值）、无文件操作、无命令执行、无 include/require、无数据库调用、无输出到响应的 echo/print、无加密或哈希逻辑。唯一的外部符号 DVWA_WEB_PAGE_TO_ROOT 为常量，非攻击者可控。因此不存在可闭合的 source→sink 利用链，未发现满足 CVE 申报条件的漏洞。surface_notes 中关于 LFI/命令注入/弱哈希/硬编码密钥的推测均为基于文件体量的 llm_inferred 推断，代码正文不支持，故不报告。未覆盖范围：无 endpoints 清单、无部署配置（php.ini/allow_url_include）、无依赖清单，无法评估第三方组件与部署层风险；DVWA_WEB_PAGE_TO_ROOT 的定义文件不在 code_pack 内，视为不存在。

未覆盖 / 证据缺口：
- 无 HTTP 端点与参数清单，无法确认外部可控输入形态
- 缺少部署配置（Web 服务器、php.ini、allow_url_include）
- 缺少依赖清单与版本信息，无法评估第三方组件 CVE
- DVWA_WEB_PAGE_TO_ROOT 常量定义文件不在 code_pack 内，未审计

## 3. Findings

### F-1: 033 客户端校验绕过（CWE-602）

- **类型**：`client_side_validation` / CWE-602
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`033.php:1-2`
- **来源**：`rule`

**描述**

证据仅覆盖 033.php 第 1-2 行：该文件只做了一件事——把外部脚本 vulnerabilities/javascript/source/medium.js 通过 <script src> 注入页面 body（033.php:2，$page['body'] .= '<script src="' . DVWA_WEB_PAGE_TO_ROOT . 'vulnerabilities/javascript/source/medium.js"></script>'）。也就是说，校验逻辑位于客户端 JS 文件 medium.js 中，而该文件不在本次 code_pack 内，服务端是否存在对应的重复校验（PHP 侧对提交参数的检查）同样没有给出任何代码。攻击者输入点应为浏览器端提交给该 JS 校验逻辑的表单参数，但具体参数名、提交路由、服务端接收变量均无源码证据。因此“客户端校验可被绕过”目前只是基于“校验放在 JS 里”的语义推断，缺少 source→sink 的闭合链：既没有看到被绕过的具体校验函数，也没有看到绕过之后到达的服务端危险操作。

**source / sink**

- source：client `external JavaScript`（033.php）
- sink：033.php:2 $page[ 'body' ] .= '<script src="' . DVWA_WEB_PAGE_TO_ROOT . 'vulnerabilities/javascript/source/medium.js"></script>';

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `033.php:2` | 客户端脚本参与校验；需同时审计服务端是否重复校验 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /033（ANY）的 客户端校验绕过 POC。注入点：ANY 参数 external JavaScript；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/033'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 客户端校验绕过 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/033?external JavaScript=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-2ffadbadfdc4`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

证据不足。若后续确认服务端未重复校验，则影响为绕过前端约束直接提交非法值（例如越权修改/写入本应被前端限制的数据）；但当前输入未提供服务端处理代码，无法确认实际影响面（是否导致数据篡改、越权或仅前端提示失效）。

**CVE / CWE 论证**

CWE-602（Client-Side Enforcement of Server-Side Security）：安全决策依赖客户端。外部可达性方面，033.php 为 DVWA 的 JavaScript 攻击模块页面，属可远程访问的 Web 路由，通常无需认证即可访问（DVWA 默认低安全级别下）。但利用链未闭合：缺少 medium.js 的校验内容与服务端接收/处理该输入的代码，无法证明“绕过客户端校验即可达成服务端状态变更”。因此不满足 CVE 级别的完整论证，仅保留为待补证的候选。

**修复建议**

1) 在服务端（PHP）对同一输入重复执行与客户端等价的校验，客户端校验仅作为体验优化；2) 对提交值使用白名单枚举/正则严格匹配，并在服务端做类型与长度约束；3) 校验失败时返回明确错误而非静默放行；4) 若涉及状态变更，补充服务端授权检查（会话/角色）与 CSRF token；5) 将 medium.js 纳入审计范围以确认其校验语义，避免前后端规则不一致。

**验证说明**

静态证据：入口 ANY /033；source=client/external JavaScript；sink=033.php:2；规则 php-client-validation。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：033.php:2 通过 $page['body'] .= '<script src="...medium.js"></script>' 引入客户端校验脚本 → 浏览器加载 medium.js 并在前端执行校验（medium.js 内容未提供）→ 攻击者可用代理/禁用 JS/直接构造请求跳过该校验 → 请求到达服务端处理逻辑（该逻辑未在 code_pack 中出现，无法确认是否重复校验）→ 若服务端缺失校验则非法值被接受。链条在第 3 步之后断裂，缺少服务端接收变量与危险汇点，故为 llm_inferred 级别推断。
PocWriter 建议（未采纳，缺少端点 /033）：针对 033.php:2 的客户端校验绕过（CWE-602）POC 文本。源码第 2 行将外部输入（query 参数 `external JavaScript`）直接用于客户端侧校验逻辑，服务端未做等价校验，攻击者可通过构造参数值绕过前端限制。注入点为 query 参数 `external JavaScript`，目标统一使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /033）：符合 CWE-602（Client-Side Enforcement of Server-Side Security）。漏洞位于可交付代码 033.php:2，外部输入来自 query 参数 `external JavaScript`，source→sink 链在给定代码范围内静态闭合，未发现有效服务端净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅限授权测试。脚本为文本参考，不自动执行；执行前须将 TARGET 替换为授权目标并人工确认。request.http 中参数名含空格，实际发送时建议使用 URL 编码形式 `external%20JavaScript=SUNSET_PROBE`。未覆盖范围：code_pack 之外的文件与运行时行为未审计。

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
| safety_guard | 安全防护 | 2.67 | 是 |
| surface_mapper | 攻击面测绘 | 6.35 | 是 |
| deep_finder | LLM 深挖 | 3.09 | 是 |
| candidate_screener | 候选筛选 | 3.6 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.59 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.4 | 是 |
| coordinator | 管线协调 | 5.55 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
