# 落日二号乙漏洞挖掘报告 — 20261031-010539-e1084d

- 生成时间：2026-10-30T17:06:06.729120+00:00
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

本次汇总仅含 1 条已去重 finding：052.php 第 11 行附近的 name 参数反射型 XSS（medium，llm_inferred，带 POC）。该 POC 为静态/HTTP 文本工件，未做动态验证。最高危即此条 XSS，风险等级 medium；POC 齐全度 1/1，但仅覆盖单一类型。surface_notes 指出 052.php 第 3 行为唯一外部输入入口，而 sink_hot_files 为空，说明汇点识别不完整，需人工沿第 3 行变量追踪至第 14 行。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 409 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 052.php（14 行）。已逐行审计：第 3 行 header 关闭 X-XSS-Protection；第 6 行读取 $_GET['name']；第 8 行 preg_replace 黑名单过滤 script；第 11 行拼接输出。确认一条反射型 XSS 链（黑名单可绕过）。未发现 SQL 拼接、文件操作、命令执行、include/eval、反序列化等其它 sink；无认证/会话/Cookie/加密相关代码，配置类攻击面（weak_crypto/weak_hash/insecure_cookie 等）无证据。sink_hot_files 为空与源码一致（无 exec/system/file 系列调用）。未覆盖范围：无端点清单与部署配置，无法确认实际路由与运行环境；无依赖清单。

未覆盖 / 证据缺口：
- 无 HTTP 端点清单与 Web 服务器配置，实际可达路由未确认
- 无依赖清单，第三方组件 CVE 未评估
- 无认证/会话/Cookie 相关代码，配置类攻击面未覆盖
- XSS 绕过需动态验证响应回显与浏览器行为

## 3. Findings

### F-1: 052.php 中 name 参数反射型 XSS：preg_replace 黑名单可被绕过

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.87`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`052.php:6-11`
- **来源**：`llm_finding`

**描述**

052.php 第 6 行从 $_GET['name'] 读取外部输入，第 8 行用正则 /<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i 试图删除 <script 标签，第 11 行把处理后的 $name 直接拼进 "<pre>Hello {$name}</pre>" 并输出到响应。该黑名单只匹配“< 与 script 之间任意字符”的单一模式，可用其它 HTML 标签（如 <svg onload=...>、<img src=x onerror=...>）或大小写/嵌套变形绕过；第 3 行还显式发送 X-XSS-Protection: 0 关闭浏览器 XSS 过滤器，进一步降低利用门槛。攻击者可构造恶意链接诱导受害者访问，在受害者浏览器上下文执行任意 JS，窃取会话或发起敏感操作。

**source / sink**

- source：query `name`（052.php）
- sink：052.php:11 第 11 行字符串拼接 $html .= "<pre>Hello {$name}</pre>" 后输出到 HTTP 响应

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `052.php:6` | 检查 $_GET 中是否存在 name 且非 NULL，确认外部输入入口 | 原始攻击者字符串 |  |
| 2 | `052.php:8` | preg_replace 用黑名单正则删除形如 <...s...c...r...i...p...t 的子串 | 仅过滤 script 关键字，其它标签与事件属性原样保留 | 黑名单只针对 script 标签，未做 HTML 实体编码；使用 <svg onload>、<img onerror> 等不含 script 的标签即可绕过 |
| 3 | `052.php:11` | 过滤后的 $name 直接拼入 HTML 片段并输出 | 未编码的 HTML/JS 注入到响应体 |  |

**POC**

针对 /052.php（GET）的反射型跨站脚本（CWE-79）POC。注入点为 GET 查询参数 name，源码 052.php:11 处将外部输入直接输出到响应，未做 HTML 编码。目标地址统一使用 TARGET 占位符，仅限授权测试。

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

反射型 XSS，可在受害者浏览器上下文执行任意 JavaScript，窃取 Cookie/会话令牌、伪造请求执行敏感操作；第 3 行关闭 X-XSS-Protection 使浏览器内置防护失效。

**CVE / CWE 论证**

CWE-79 跨站脚本。外部 GET 参数 name 无需认证即可注入，黑名单过滤可被非 script 标签绕过，链闭合；属于经典反射型 XSS 教学样本（类似 DVWA XSS reflected low/medium）。

**修复建议**

对输出到 HTML 的变量使用 htmlspecialchars($name, ENT_QUOTES, 'UTF-8') 进行上下文编码；移除 X-XSS-Protection: 0；不要依赖黑名单正则过滤，改用白名单或输出编码。

**验证说明**

需动态确认响应确实原样回显未编码的 name 值，以及目标环境是否启用浏览器 XSS 过滤；源码层面链已闭合。
模型 POC 要点：构造包含非 script 标签事件处理器的 name 参数，诱导受害者点击后在浏览器执行 JS
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /052.php）：符合 CWE-79（跨站脚本）。漏洞位于 052.php:11，外部输入来自 GET 查询参数 name，source→sink 链在给定代码范围内静态闭合，未发现有效净化/编码；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。若需手工复现，请将 TARGET 替换为已授权目标后自行执行；禁止使用 curl|sh 等自动执行方式。request.http 中的 Content-Length 仅对带 body 的请求有意义，本 GET 请求可忽略该头。

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
| safety_guard | 安全防护 | 2.36 | 是 |
| surface_mapper | 攻击面测绘 | 5.77 | 是 |
| deep_finder | LLM 深挖 | 8.01 | 是 |
| candidate_screener | 候选筛选 | 2.87 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.59 | 是 |
| coordinator | 管线协调 | 3.97 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
