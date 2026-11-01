# 落日二号乙漏洞挖掘报告 — 20261031-164816-2208aa

- 生成时间：2026-10-31T08:48:47.640247+00:00
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

本次汇总仅含 1 条已去重 finding：052.php 第 3 行读取的 name 参数经不完整黑名单过滤后在第 11 行附近反射输出，构成反射型 XSS（medium，LLM-4be6b4e0336a），已附 POC（HTTP 型，可动态复现路径清晰）。最高危即该条 medium XSS，无 high/critical。POC 齐全度：1/1 finding 带 POC，但该 POC 属静态推导+HTTP 请求文本，未做动态验证。整体攻击面极窄（单文件 14 行 PHP，无框架、无端点声明），surface_notes 指出 sink 热点为空、第 3 行 source 下游流向需人工确认，该点已部分被 XSS finding 覆盖，但文件/命令/SQL 类汇点仍未覆盖。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 409 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 052.php（14 行）。第 3 行 header("X-XSS-Protection: 0") 关闭浏览器 XSS 过滤；第 6 行读取 $_GET['name']，第 8 行用仅针对 script 关键字的黑名单正则过滤，第 11 行将结果直接拼入 HTML 输出，构成反射型 XSS，链完整闭合。未发现 SQL/命令/文件/反序列化等其它 sink（文件中不存在相关函数）。未覆盖范围：无 php.ini/Web 服务器配置、无端点清单与部署说明，无法确认 register_globals、WAF、实际访问路径；$html 变量在第 11 行前未初始化，属代码质量问题但不改变 XSS 结论。

未覆盖 / 证据缺口：
- 缺少运行时配置（php.ini、Web 服务器、WAF）
- 无实际部署路径与请求样例
- $html 未初始化，需确认错误显示设置是否影响响应

## 3. Findings

### F-1: 052.php 中 name 参数经不完整黑名单过滤导致反射型 XSS

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.87`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`052.php:6-11`
- **来源**：`llm_finding`

**描述**

脚本从 $_GET['name'] 读取用户输入，仅用 preg_replace 正则 '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i' 删除形如 <script 的片段，随后把结果直接拼进 "<pre>Hello {$name}</pre>" 输出到响应。该正则只匹配以 '<' 开头、且 s/c/r/i/p/t 顺序出现的字符串，无法覆盖其它标签（如 <img>、<svg>、<iframe>）或事件处理器（onerror/onload），因此攻击者可注入任意 HTML/JS。同时第 3 行显式设置 X-XSS-Protection: 0，关闭了浏览器内置 XSS 过滤器，进一步降低利用门槛。

**source / sink**

- source：query `name`（052.php）
- sink：052.php:11 $html .= "<pre>Hello {$name}</pre>" 直接输出到 HTTP 响应

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `052.php:6` | 检查 $_GET 中是否存在 name 且非 NULL，攻击者通过 URL 查询串控制该值 | 原始攻击者字符串 |  |
| 2 | `052.php:8` | preg_replace 仅删除匹配 <...s...c...r...i...p...t 的片段，对不含该序列的标签或事件属性不做任何处理 | 经过不完整黑名单过滤，仍保留 <img>/<svg>/onerror 等危险内容 | 黑名单只针对 script 关键字，可用 <img src=x onerror=...> 等标签绕过 |
| 3 | `052.php:11` | 过滤后的值被拼进 HTML 片段并输出到响应体，浏览器按 HTML 解析执行 | 未编码的 HTML/JS 注入响应 |  |

**POC**

针对 /052.php（GET）的反射型跨站脚本（XSS）POC。源码 052.php:11 将 GET 参数 name 的值直接写入响应，未做 HTML 编码，导致脚本在受害者浏览器执行。目标地址统一使用 TARGET 占位符。

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

攻击者可在受害者浏览器上下文执行任意 JavaScript，窃取会话/凭据、伪造页面内容或诱导敏感操作；由于 X-XSS-Protection 被关闭，现代浏览器不再提供额外拦截。

**CVE / CWE 论证**

CWE-79 跨站脚本。外部无需认证即可通过 GET 参数触发，source→sink 链在 052.php:6→8→11 完整闭合，黑名单可被非 script 标签绕过。

**修复建议**

对输出使用 htmlspecialchars($name, ENT_QUOTES, 'UTF-8') 进行上下文编码；移除 X-XSS-Protection: 0；不要依赖黑名单过滤，改用输出编码或 CSP。

**验证说明**

需在真实浏览器确认 onerror/onload 执行；确认 $html 变量未定义时的 PHP notice 不影响输出；确认部署环境未额外加 WAF 或输出编码。
模型 POC 要点：向 052.php 的 name 参数注入不含 script 关键字的 HTML 事件处理器，触发脚本执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /052.php）：符合 CWE-79（跨站脚本）。漏洞位于 052.php:11，外部输入来自查询参数 name，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅保留文本工件，不执行。curl 示例：curl -sS -i -X GET 'http://TARGET:8080/052.php?name=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'。注意 request.http 中 Content-Length 与 GET 无 body 不一致，实际发送时不应带 body 与 Content-Length；端口 8080 需按实际部署调整。仅限授权测试。

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
| safety_guard | 安全防护 | 4.79 | 是 |
| surface_mapper | 攻击面测绘 | 4.81 | 是 |
| deep_finder | LLM 深挖 | 7.78 | 是 |
| candidate_screener | 候选筛选 | 2.8 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.38 | 是 |
| coordinator | 管线协调 | 6.1 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
