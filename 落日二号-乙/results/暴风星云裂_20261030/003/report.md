# 落日二号乙漏洞挖掘报告 — 20261030-224521-ad21dc

- 生成时间：2026-10-30T14:45:56.278355+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\003.zip`
- 输入模式：`zip`
- SHA256：`06085614e8d510ff9f2f368ced0a790b64e5926adc00f379d25132aa3a2a79d0`
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

本次汇总仅含 1 条已去重 finding：003.php 中通过 $_SERVER['REQUEST_URI'] 反射进入 JavaScript 上下文的反射型 XSS（high，LLM-d891d8de8c0d，行至 51），已附带 POC，属 HTTP 可复现类型（POC 为文本工件，未执行、未动态验证）。最高危即此条。POC 齐全度：1/1 有 POC，但均为静态推断产物，未经动态确认。其余攻击面（命令注入、SQL 注入、路径穿越、SSRF、文件包含、二次注入、弱算法/弱随机/不安全 Cookie/信任边界）在 surface_notes 中被列为优先审计点，但本次 findings 未覆盖，需人工复核；输入未提供 003.php 代码正文，所有结论限于文件清单与热点计数层面。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3115 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计唯一文件 003.php（1-98 行）。该脚本为单页 PHP，读取 $_SERVER['REQUEST_URI'] 与 $_SERVER['PHP_SELF']，无数据库、无命令执行、无文件包含、无反序列化汇点。确认一条闭合链：REQUEST_URI 经 str_replace 弱过滤后拼入内联 <script> 的单引号字符串，构成反射型 XSS（第 3/4/31/51 行）。第 83 行 $_SERVER['PHP_SELF'] 拼入 form action 属性，同样未编码，但 PHP_SELF 受服务器规范化限制、可利用性弱于 REQUEST_URI，未单独立项。脚本内无 md5/sha1/rand/setcookie/openssl 等调用，weak_hash/weak_crypto/weak_random/insecure_cookie 无证据；未发现信任 X-Forwarded-For 等头做鉴权的逻辑。输入中无诱导性文本，无 prompt_injection 证据。

未覆盖 / 证据缺口：
- 无部署配置（WAF、URL 重写、PHP 版本），无法确认 REQUEST_URI 是否被前置规范化
- endpoints 为空，实际暴露路径与 HTTP 方法仅按源码推断
- 第 83 行 PHP_SELF 反射未单独立项，需人工确认服务器对 PHP_SELF 的处理
- 无数据库/依赖清单，无法评估其它组件风险

## 3. Findings

### F-1: 003.php 通过 REQUEST_URI 反射注入 JavaScript 上下文（反射型 XSS）

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.87`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`003.php:3-51`
- **来源**：`llm_finding`

**描述**

脚本第 3 行直接读取 $_SERVER['REQUEST_URI']，第 4 行仅用 str_replace 删除字面量 "/vulnerabilities/api/"，未做任何 HTML/JS 编码或转义；随后在第 31 行与第 51 行把 $stripped_url 拼进单引号包裹的 JavaScript 字符串（const url = '...'），并在第 6-76 行整体输出到页面。攻击者可在请求路径中注入单引号闭合 JS 字符串，进而执行任意 JavaScript。由于 REQUEST_URI 包含查询串，无需路径重写即可注入。

**source / sink**

- source：header `REQUEST_URI`（003.php:3）
- sink：003.php:51 第 31/51 行字符串拼接进 <script> 内的 JS 单引号字符串，最终随 $html 输出（第 6-76 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `003.php:3` | 读取原始请求 URI 到 $request_url | 完全攻击者可控的原始字符串 |  |
| 2 | `003.php:4` | str_replace 仅删除字面量 /vulnerabilities/api/，不处理引号、尖括号、反斜杠 | 仍含单引号/JS 代码的字符串 | 黑名单式替换只针对固定子串，单引号与分号未被过滤 |
| 3 | `003.php:31` | 拼接到 const url = '<payload>/vulnerabilities/api/v2/user/2' 的单引号字符串中 | 注入点位于 JS 字符串字面量内部 |  |
| 4 | `003.php:6` | $html 累积后输出到响应，浏览器解析执行注入的 JS | 反射到客户端执行 |  |

**POC**

针对 003.php:51 的反射型跨站脚本（CWE-79）POC。注入通道为 HTTP 请求头 `REQUEST_URI`（源码通过读取该请求头取值并输出到响应，未做 HTML 编码），入口为 GET /*。目标地址统一使用 TARGET 占位符，POC 仅为文本工件，不执行、不联网。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/*'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/*' \
  -H 'REQUEST_URI: %3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-d891d8de8c0d`
- 执行状态：未执行（`executed=False`）

**影响**

在受害者浏览器上下文执行任意 JS，可窃取会话、以受害者身份调用 /vulnerabilities/api/v2/user/2 的 PUT 接口篡改数据或提权。

**CVE / CWE 论证**

CWE-79 反射型 XSS：外部 GET 请求即可触发，无需认证，source→sink 链在单文件内闭合，仅存在可绕过的黑名单替换。

**修复建议**

对 $stripped_url 使用 json_encode 输出到 JS 上下文，或对输出做 htmlspecialchars(..., ENT_QUOTES) 并避免把 URI 拼进内联脚本；改用固定相对路径。

**验证说明**

需确认部署环境是否对 REQUEST_URI 做规范化/过滤，以及响应 Content-Type 与浏览器解析行为。
模型 POC 要点：在请求路径中注入单引号闭合 JS 字符串并执行脚本，验证反射型 XSS。仅限授权测试。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /*）：符合 CWE-79（跨站脚本）。漏洞位于可交付代码 003.php:51，外部输入来自请求头 `REQUEST_URI`，source→sink 链在给定代码范围内静态闭合，未发现有效净化/编码；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅限授权测试。保留原确定性 POC 的请求结构（GET /* + REQUEST_URI 头），仅补充前置条件与预期结果说明。目标地址固定为 TARGET，不写入真实 IP/域名；不生成自动执行脚本，不执行、不联网、不搭建沙箱。若目标实际不读取 REQUEST_URI 头（部分容器/代理会覆盖该头），需以源码 003.php:51 的实际取值方式为准再调整。

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
| safety_guard | 安全防护 | 3.65 | 是 |
| surface_mapper | 攻击面测绘 | 8.91 | 是 |
| deep_finder | LLM 深挖 | 7.67 | 是 |
| candidate_screener | 候选筛选 | 3.4 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.72 | 是 |
| coordinator | 管线协调 | 5.8 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
