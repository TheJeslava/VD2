# 落日二号乙漏洞挖掘报告 — 20261031-012249-2d747f

- 生成时间：2026-10-30T17:23:19.589721+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\054.zip`
- 输入模式：`zip`
- SHA256：`f56d8d7acab4a33d76750401c5e2eec81cfdf4ce2a39a589bd28299560fe4eb0`
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

本次汇总仅含 1 条已去重 finding：054.php 的反射型 XSS（LLM-04dd02aad740，medium），依据是 str_replace 只删除小写 <script> 标签、name 参数原样拼入 HTML，且已附带 POC（HTTP 型，可动态复现）。最高危即该条 medium XSS；POC 齐全（with_poc=1/1）。除此之外无其他类型 finding，但攻击面测绘明确指出输入未提供 054.php 源码片段、sink 热点为空，因此注入类与配置类结论均无法落地，不能据此认定其他类型不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 382 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 054.php（14 行，已完整展示 1-14 行）。逐行审计结果：第 3 行 header('X-XSS-Protection: 0') 主动关闭浏览器 XSS 过滤；第 6 行接收 $_GET['name']；第 8 行 str_replace('<script>','') 为可绕过的单次大小写敏感黑名单；第 11 行将 $name 未编码拼入 HTML 输出，构成反射型 XSS，链闭合，已作为唯一 finding 交付。其余攻击面核查：文件内无 exec/system/passthru/shell_exec 等命令执行汇点，无 mysqli_query/mysql_query 等 SQL 汇点，无 include/require 动态包含，无 file_get_contents/fopen 文件操作，无 unserialize/反序列化，无 md5/sha1/crypt 弱哈希，无 rand/mt_rand 弱随机，无 setcookie/session_set_cookie_params 不安全 Cookie 配置，无 HTTP_X_FORWARDED_FOR/REMOTE_ADDR 信任边界判断，故未产生配置类或注入类其它 finding。未覆盖范围：无 composer.json、Web 服务器配置与端点清单，无法评估部署形态与是否存在前置反向代理；若 054.php 仅作 CLI 使用则 XSS 不可外部触发，需人工确认部署方式。

未覆盖 / 证据缺口：
- 无 HTTP 端点清单与部署配置，无法确认 054.php 是否为 Web 可访问脚本
- 无 composer.json/依赖清单，无法评估第三方组件风险
- 未提供 Web 服务器与反向代理配置，无法评估 trust_boundary 运行时条件

## 3. Findings

### F-1: 054.php 反射型 XSS：str_replace 仅删除小写 <script> 标签，name 参数原样拼入 HTML

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.82`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`054.php:6-11`
- **来源**：`llm_finding`

**描述**

054.php 第 6 行从 $_GET['name'] 读取外部输入，第 8 行仅用 str_replace('<script>','',...) 做单次、大小写敏感、非递归的黑名单过滤，第 11 行把过滤后的 $name 直接拼接进 "<pre>Hello {$name}</pre>" 并输出到响应体。攻击者可用大写/混合大小写标签（<Script>、<SCRIPT>）、其它标签（<img src=x onerror=...>、<svg onload=...>）或嵌套写法（<scr<script>ipt> 经单次替换后重组为 <script>）绕过过滤，在受害者浏览器执行任意 JS。第 3 行还主动发送 X-XSS-Protection: 0，关闭浏览器内置 XSS 过滤器，进一步降低利用门槛。

**source / sink**

- source：query `name`（054.php）
- sink：054.php:11 echo/输出 $html 到 HTTP 响应体（第 11 行字符串拼接，脚本结束 ?> 后由 PHP 输出）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `054.php:6` | array_key_exists('name', $_GET) 判断参数存在，$_GET['name'] 为攻击者完全可控的查询字符串 | 原始攻击者输入，未做任何编码 | 无认证、无来源校验 |
| 2 | `054.php:8` | str_replace('<script>','',$_GET['name']) 仅做一次大小写敏感的字面替换 | 过滤后字符串，仍保留 <img onerror>、<svg onload>、<Script> 等标签；嵌套 <scr<script>ipt> 会被重组为 <script> | 黑名单只覆盖精确小写 '<script>'，大小写变体、其它标签、嵌套写法均可绕过 |
| 3 | `054.php:11` | $name 被插值进 "<pre>Hello {$name}</pre>" 并赋给 $html，随后输出到响应 | 未做 HTML 实体编码的最终 HTML 片段 | 无 htmlspecialchars/htmlentities 输出编码 |

**POC**

针对 /054.php（GET）的反射型跨站脚本（CWE-79）POC。注入点为 GET 查询参数 name，源码位置 054.php:11；payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/054.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/054.php?name=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-04dd02aad740`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

在受害者浏览器上下文执行任意 JavaScript，可窃取会话 Cookie、伪造用户操作、进行钓鱼或结合 CSRF 打点；由于页面主动关闭 X-XSS-Protection，现代浏览器也不会拦截。

**CVE / CWE 论证**

CWE-79 跨站脚本。外部无需认证即可通过 GET 参数触发，source→sink 链在 054.php:6→8→11 完整闭合，过滤为可绕过的单次黑名单替换，属典型反射型 XSS。

**修复建议**

输出前使用 htmlspecialchars($name, ENT_QUOTES, 'UTF-8') 做上下文编码；移除基于黑名单的 str_replace 过滤；删除 header('X-XSS-Protection: 0')，改为设置 Content-Security-Policy。

**验证说明**

需动态确认 PHP 配置下 $html 未初始化告警不影响输出、响应 Content-Type 为 text/html（默认），以及目标是否真实部署为 Web 可访问脚本。
模型 POC 要点：向 name 参数注入不含小写 <script> 字面量的 XSS payload，绕过 str_replace 后在响应中执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /054.php）：符合 CWE-79（跨站脚本）。漏洞位于可交付代码 054.php:11，外部输入来自 GET 查询参数 name，source→sink 链在给定代码范围内静态闭合，未发现有效输出编码/净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。目标地址统一使用 TARGET 占位符，执行前需替换为授权测试目标。request.http 中的 Content-Length 仅对带 body 的请求有意义，本 GET 请求无 body，可忽略该头。禁止在未授权环境运行。

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
| safety_guard | 安全防护 | 2.41 | 是 |
| surface_mapper | 攻击面测绘 | 7.23 | 是 |
| deep_finder | LLM 深挖 | 8.55 | 是 |
| candidate_screener | 候选筛选 | 2.44 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.11 | 是 |
| coordinator | 管线协调 | 4.89 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
