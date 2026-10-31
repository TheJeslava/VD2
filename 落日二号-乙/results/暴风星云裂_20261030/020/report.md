# 落日二号乙漏洞挖掘报告 — 20261030-224736-60aa5d

- 生成时间：2026-10-30T14:48:08.546024+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\020.zip`
- 输入模式：`zip`
- SHA256：`f7bc24fccdcc53d2a999c3468bedf97d91c239734baf4f227ae7ef495dbe0b26`
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

本次汇总仅含 1 条已去重 finding：020.php 第 2 行读取的 POST 参数未经编码即拼接进 <script src>，构成反射型 XSS（high，LLM-370901c0cb4c），且已附带 POC，属本次最高危项。该 POC 为 HTTP 型，理论上可动态复现，但本次未做任何动态验证，仅为静态源码推断（llm_inferred）。除该 XSS 外无其他类型 finding，无二次注入链。整体项目为单文件 PHP（020.php，27 行），无框架、无路由、无端点清单，攻击面集中在单一参数处理路径。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1199 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 020.php（27 行，全量通读）。发现 1 条闭合链：POST 参数 include 在 020.php:13-17 未编码拼接进 <script src> 属性，构成反射型 XSS；CSP（020.php:3-5）白名单包含 unpkg.com/cdn.jsdelivr.net/pastebin.com 等可托管任意内容的域，无法阻止脚本执行。未发现命令执行、文件包含、SQL、反序列化等其它 sink（文件中无 exec/system/include/file 系列调用）。未覆盖范围：无 php.ini/Web 服务器配置/composer.json，无法确认运行环境与危险函数禁用情况；endpoints 为空，无法确认访问路径与认证要求；无版本控制信息，无法判断是否为示例代码。

未覆盖 / 证据缺口：
- 无 Web 服务器/php.ini 配置，无法确认部署路径与公网可达性
- 无认证/会话线索，无法判断是否需要登录
- CSP 绕过需真实浏览器动态验证
- 无版本控制信息，无法判断是否为示例/测试代码

## 3. Findings

### F-1: 020.php POST 参数 include 未编码直接拼接进 <script src> 导致反射型 XSS（CSP 白名单可绕过）

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`020.php:13-17`
- **来源**：`llm_finding`

**描述**

020.php 第 13-17 行读取 $_POST['include']，未做任何 HTML 实体编码或 URL 白名单校验，直接以单引号包裹拼接到 <script src='...'></script> 中并输出到响应体。攻击者可提交包含单引号的 payload 闭合 src 属性，注入任意 HTML/JS（如 onerror、<svg onload>、<iframe> 等）。虽然第 3-5 行设置了 CSP script-src 白名单，但该 CSP 允许 unpkg.com、cdn.jsdelivr.net、code.jquery.com、pastebin.com 等可托管任意内容的公共 CDN/粘贴站，攻击者可把恶意 JS 托管在这些被允许的域上，从而在 CSP 生效的情况下依然执行脚本；同时注入的 inline 事件处理器/非 script 标签（如 <img onerror>）在部分浏览器与 CSP 配置下亦可触发。该页面本身即为 CSP 绕过练习页，说明其设计意图就是演示可被绕过的 CSP。

**source / sink**

- source：body `include`（020.php）
- sink：020.php:17 字符串拼接后写入 $page['body'] 并输出到 HTML 响应（<script src='...'> 属性上下文）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `020.php:13` | isset($_POST['include']) 判断外部 POST 参数是否存在，未做任何过滤 | 原始攻击者可控字符串 |  |
| 2 | `020.php:14-16` | 将 $_POST['include'] 直接以单引号包裹拼接到 <script src='...'></script> 模板中 | 未编码的原始字符串进入 HTML 属性上下文 | 无 htmlspecialchars/实体编码，无 URL 白名单校验，单引号可闭合 src 属性 |
| 3 | `020.php:18-27` | $page['body'] 最终随页面输出，注入的标签/事件处理器被浏览器解析执行 | 注入的 HTML/JS 在受害者浏览器执行 |  |

**POC**

针对 /020.php（POST）的反射型跨站脚本（XSS）POC。注入点为 POST 表单参数 include，该参数值未经 HTML 编码即被输出到响应页面，导致脚本在受害者浏览器中执行。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/020.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/020.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'include=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-370901c0cb4c`
- 执行状态：未执行（`executed=False`）

**影响**

反射型 XSS：攻击者可诱导受害者提交恶意 include 值，在目标域上下文执行任意 JS，窃取会话/凭证、发起 CSRF、篡改页面内容；CSP 因白名单包含可托管任意内容的公共 CDN 而无法有效防护。

**CVE / CWE 论证**

CWE-79 跨站脚本。外部可达（HTTP POST 参数）、无需认证、source→sink 链在 020.php:13-17 完整闭合，无任何编码/校验。

**修复建议**

对 include 值使用 htmlspecialchars($v, ENT_QUOTES) 编码后再输出；或仅允许 https 且域名在严格白名单内的 URL，并移除 CSP 中可托管任意内容的公共 CDN/粘贴站。

**验证说明**

需确认 020.php 的实际部署路径与是否公网可达；CSP 绕过依赖浏览器对 onerror 等事件处理器与白名单 CDN 的处理，建议在授权环境用真实浏览器验证。
模型 POC 要点：向 020.php 提交 include 参数，闭合 script src 属性并注入事件处理器；或注入指向 CSP 白名单域（unpkg.com/cdn.jsdelivr.net）的外部脚本以绕过 CSP。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /020.php）：符合 CWE-79（跨站脚本）。漏洞位于可交付代码 020.php:17，外部输入来自 POST body 参数 include，source→sink 链在静态审计中闭合，未发现有效输出编码/净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为已获授权的目标，并手动运行。原始确定性请求结构（POST /020.php，参数 include）予以保留，仅补充说明与预期结果。request.http 中 Content-Length 需按实际编码后字节数校准。

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
| safety_guard | 安全防护 | 3.51 | 是 |
| surface_mapper | 攻击面测绘 | 5.93 | 是 |
| deep_finder | LLM 深挖 | 8.95 | 是 |
| candidate_screener | 候选筛选 | 2.47 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.48 | 是 |
| coordinator | 管线协调 | 5.95 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
