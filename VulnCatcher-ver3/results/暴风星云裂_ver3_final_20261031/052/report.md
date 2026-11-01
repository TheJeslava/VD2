# 落日二号乙漏洞挖掘报告 — 20261031-014445-54a09e

- 生成时间：2026-10-30T17:45:12.442348+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\052.zip`
- 输入模式：`zip`
- SHA256：`6b53fa2c4a30c16747b1ae8a0236ae3f7fb52d1a4bc7e7999805f539e733c540`
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

本次汇总仅含 1 条已去重 finding：052.php 第 11 行附近的反射型 XSS（LLM-4be6b4e0336a，medium，llm_finding），其成因是 name 参数经 preg_replace 黑名单过滤后仍可被绕过并回显；该条已附带 POC（has_poc=true），属 HTTP 型 POC，但仅为静态源码推断，未做动态验证。最高危即此条 medium XSS，无 high/critical 项。POC 齐全度：1/1 有 POC，但全部为静态证据，不能宣称可动态复现。需强调：surface_notes 明确指出输入未提供 052.php 的代码正文与 sink 热点，因此注入类与配置类候选均属“未覆盖”，不得据此认定不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 409 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 052.php（14 行），已完整通读。第 3 行 source 热点实为 `header("X-XSS-Protection: 0")`，真正的外部输入在第 6 行 `$_GET['name']`；第 8 行 preg_replace 黑名单过滤后于第 11 行直接拼入 HTML 输出，构成反射型 XSS，且第 3 行主动关闭浏览器 XSS 防护，链路闭合。未发现命令执行、文件包含、SQL、反序列化等其它 sink（文件中不存在 system/exec/include/file_get_contents/eval 等调用）。未闭合/未覆盖：无端点清单与部署配置，无法确认脚本是否经 Web 服务器对外暴露、是否有认证层；无 composer 依赖，无法评估第三方组件。

未覆盖 / 证据缺口：
- 无 Web 服务器/php.ini 配置，无法确认外部可达性与响应 Content-Type
- 无端点/路由与认证信息
- 无依赖清单，未评估第三方组件 CVE

## 3. Findings

### F-1: 052.php 中 `name` 参数反射型 XSS：preg_replace 黑名单可被绕过

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.87`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`052.php:6-11`
- **来源**：`llm_finding`

**描述**

脚本读取 `$_GET['name']`，用正则 `/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i` 删除形如 `<script` 的片段，然后把结果直接拼进 `$html .= "<pre>Hello {$name}</pre>"` 输出。该正则只匹配 `<` 与 `script` 之间夹任意字符、且各字母间可夹任意字符的单一序列，属于典型黑名单：任何不含字面 `script` 的标签（如 `<img src=x onerror=...>`、`<svg onload=...>`）完全不受影响；同时第 3 行显式发送 `X-XSS-Protection: 0`，主动关闭浏览器内置 XSS 过滤器，进一步降低利用门槛。攻击者可构造链接诱导受害者访问，在受害者浏览器上下文执行任意 JS，窃取会话或发起操作。

**source / sink**

- source：query `name`（052.php）
- sink：052.php:11 `$html .= "<pre>Hello {$name}</pre>"` 直接输出到响应体（第 11 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `052.php:6` | 检查 GET 参数 name 存在且非 NULL，攻击者完全可控 | 原始字符串，未编码 | 无任何前置校验 |
| 2 | `052.php:8` | preg_replace 仅删除匹配 `<...s...c...r...i...p...t` 的片段 | 黑名单过滤后的字符串 | 正则只针对字面 script 标签，`<img onerror>`、`<svg onload>`、`<body onload>` 等不含 script 的标签原样保留；大小写/嵌套写法也可绕过 |
| 3 | `052.php:11` | 过滤结果拼入 HTML 并输出到响应 | 未做 HTML 实体编码，直接进入响应体 | 无 htmlspecialchars 等输出编码 |
| 4 | `052.php:3` | 响应头 X-XSS-Protection: 0 关闭浏览器 XSS 审计 | 响应头 | 移除浏览器侧最后一道缓解 |

**POC**

针对 /052.php（GET）的反射型跨站脚本（CWE-79）POC。注入点为 GET 查询参数 name，源码 052.php 第 11 行将外部输入直接输出到响应中且未做 HTML 编码，source→sink 链静态闭合。目标地址统一使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/052.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/052.php?name=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-4be6b4e0336a`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

反射型 XSS：攻击者可诱导任意用户（含管理员）在站点域下执行任意 JavaScript，窃取 Cookie/令牌、伪造请求、篡改页面内容。

**CVE / CWE 论证**

CWE-79。外部 GET 参数直达 HTML 输出，无认证要求，黑名单过滤可被非 script 标签绕过，且脚本主动关闭 X-XSS-Protection，链路闭合。

**修复建议**

对输出使用 htmlspecialchars($name, ENT_QUOTES, 'UTF-8') 进行上下文编码；移除 X-XSS-Protection: 0；不要依赖标签黑名单，改用白名单或纯文本输出。

**验证说明**

需确认 052.php 实际由 Web 服务器解析执行（而非 CLI 示例），以及响应 Content-Type 为 text/html 使浏览器渲染；未提供部署配置，故置信度未取更高。
模型 POC 要点：向 name 参数注入不含 script 字面量的 HTML 事件处理器，验证脚本原样回显并执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /052.php）：符合 CWE-79（跨站脚本）。漏洞位于可交付代码 052.php 第 11 行，外部输入来自 GET 查询参数 name，source→sink 链已静态闭合，未发现有效净化/编码，具备远程触发条件。证据等级：llm_inferred（基于源码静态推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。脚本中的 curl 命令仅供授权测试人员手动替换 TARGET 后使用，禁止自动执行。request.http 中的 Content-Length 仅作示例，实际以发送工具计算为准。

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
| `xss` | CWE-79 | 是 | 1 |
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
| safety_guard | 安全防护 | 2.3 | 是 |
| surface_mapper | 攻击面测绘 | 4.96 | 是 |
| deep_finder | LLM 深挖 | 7.97 | 是 |
| candidate_screener | 候选筛选 | 2.67 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.14 | 是 |
| coordinator | 管线协调 | 4.9 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
