# 落日二号乙漏洞挖掘报告 — 20261031-002444-d222b8

- 生成时间：2026-10-30T16:25:15.926486+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\052.zip`
- 输入模式：`zip`
- SHA256：`6b53fa2c4a30c16747b1ae8a0236ae3f7fb52d1a4bc7e7999805f539e733c540`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`high`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总仅含 1 条已去重 finding：052.php 反射型 XSS（high，LLM-4be6b4e0336a），证据为 preg_replace 黑名单可被嵌套标签绕过、name 参数直接回显，行号落在 052.php 第 11 行（文件共 14 行），已附带 POC（HTTP 型，可动态复现路径存在，但本次未执行、未做动态验证）。最高危即该条 XSS。POC 齐全度：1/1 finding 有 POC，但均为静态审计推导，未经动态确认。整体攻击面极小（单文件 PHP、无框架、无路由清单、无认证线索），证据量少，其余类型只能停留在待复核层面。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 409 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 052.php（14 行），已全量审阅。第 6 行 $_GET['name'] 为唯一外部输入，第 8 行黑名单正则仅过滤 script 标签，第 11 行未编码直接回显，构成反射型 XSS；第 3 行主动关闭 X-XSS-Protection 加剧风险。未发现命令执行、SQL、文件包含、反序列化、SSRF 等 sink；无硬编码凭据、弱哈希/弱随机/Cookie 相关调用。未覆盖范围：无 php.ini/Web 服务器配置、无路由与认证信息，无法确认部署方式与访问路径；若为 CLI 脚本则 XSS 不可远程触发，需人工确认。

未覆盖 / 证据缺口：
- 无法确认 052.php 是否由 Web 服务器对外暴露（CLI 还是 Web 模式）
- 缺少 php.ini/Web 服务器配置与依赖清单
- 无认证/授权机制信息
- 无外部扫描（AWVS）证据

## 3. Findings

### F-1: 052.php 反射型 XSS：preg_replace 黑名单可被嵌套标签绕过并直接回显 name 参数

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`052.php:6-11`
- **来源**：`llm_finding`

**描述**

052.php 第 6 行从 $_GET['name'] 读取外部输入，第 8 行用正则 /<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i 试图删除 <script 标签，第 11 行将处理后的 $name 直接拼接进 "<pre>Hello {$name}</pre>" 输出。该正则只匹配包含连续 s-c-r-i-p-t 字母序列的标签，无法覆盖其它可执行脚本的标签（如 <img src=x onerror=...>、<svg onload=...>、<iframe srcdoc=...>），也无法覆盖大小写/嵌套构造之外的任意事件处理器。同时第 3 行显式发送 header("X-XSS-Protection: 0")，主动关闭浏览器内置 XSS 过滤器，进一步降低利用门槛。攻击者可构造恶意链接诱导受害者访问，在受害者浏览器上下文执行任意 JavaScript，窃取会话 Cookie、发起 CSRF 或篡改页面内容。

**source / sink**

- source：query `name`（052.php:6）
- sink：052.php:11 第 11 行字符串拼接 $html .= "<pre>Hello {$name}</pre>" 后输出到 HTTP 响应体

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `052.php:6` | 通过 array_key_exists 检查并读取 $_GET['name']，非空即进入处理分支 | 攻击者完全可控的原始字符串 |  |
| 2 | `052.php:8` | preg_replace 用黑名单正则删除形如 <...s...c...r...i...p...t...> 的标签 | 仅含 script 字母序列的标签被删除；<img onerror>、<svg onload> 等不含该序列的标签原样保留 | 黑名单只针对 script 关键字，未做 HTML 实体编码，任何非 script 的可执行标签或事件属性均可绕过 |
| 3 | `052.php:11` | 处理后的 $name 被直接拼入 HTML 片段并输出 | 未编码的 HTML/JS 注入到响应体 |  |

**POC**

针对 /052.php（GET）的反射型跨站脚本（CWE-79）POC。注入点为 GET 参数 name，源码 052.php:11 将外部输入直接输出到响应中且未做 HTML 编码，source→sink 链静态闭合。目标地址统一使用 TARGET 占位符。

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

在受害者浏览器上下文执行任意 JavaScript，可窃取会话 Cookie、劫持用户操作、发起 CSRF、钓鱼篡改页面；第 3 行关闭 X-XSS-Protection 使旧版浏览器防护失效。

**CVE / CWE 论证**

CWE-79 跨站脚本。外部 GET 参数 name 无需认证即可注入，黑名单过滤可被非 script 标签绕过，输出未编码，链路闭合。

**修复建议**

移除黑名单式 preg_replace，改用 htmlspecialchars($name, ENT_QUOTES, 'UTF-8') 对输出进行上下文编码；删除 header("X-XSS-Protection: 0")；设置 Content-Security-Policy。

**验证说明**

需确认 052.php 实际由 Web 服务器解析执行（而非 CLI），以及响应 Content-Type 为 text/html 使浏览器渲染注入标签。
模型 POC 要点：构造包含 img onerror 事件处理器的 name 参数，绕过 script 黑名单后在受害者浏览器执行 JS
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /052.php）：符合 CWE-79（跨站脚本）。漏洞位于可交付代码 052.php:11，外部输入来自 query 参数 name，source→sink 链已静态闭合，未发现有效净化/编码，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，管线不执行、不联网、不搭建沙箱。目标地址统一使用 TARGET 占位符，请替换为授权目标后手动执行；request.http 中 Content-Length 与 GET 请求体不匹配，实际发送时以 URL 查询串为准，可忽略该头部。

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
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.05 | 是 |
| surface_mapper | 攻击面测绘 | 7.39 | 是 |
| deep_finder | LLM 深挖 | 7.45 | 是 |
| candidate_screener | 候选筛选 | 3.46 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.46 | 是 |
| coordinator | 管线协调 | 5.41 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
