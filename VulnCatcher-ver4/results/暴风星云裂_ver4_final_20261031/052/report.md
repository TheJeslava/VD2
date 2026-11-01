# 落日二号乙漏洞挖掘报告 — 20261031-173349-79efaa

- 生成时间：2026-10-31T09:34:19.457215+00:00
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

本次汇总仅含 1 条已去重 finding：052.php 反射型 XSS（LLM-4be6b4e0336a，medium），依据是 preg_replace 黑名单可被嵌套标签绕过，已附带 POC（HTTP 型，可动态复现，但本次未执行验证）。最高危即该条 medium XSS，无 high/critical。POC 齐全度：1/1 finding 有 POC，但均为静态审计推断产物，未经动态验证。攻击面测绘指出 052.php:3 为唯一污点源，并列出 path_traversal/LFI-RFI、command_injection/eval、输出回显四类优先区域，其中仅 xss 一类被 finding 覆盖，其余三类无对应 finding，需人工复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 409 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单文件 052.php（14 行）。已审计其唯一外部输入点 $_GET['name']（第 6 行）及其下游：第 8 行 preg_replace 黑名单过滤、第 11 行 HTML 输出。确认存在可绕过的反射型 XSS（黑名单非递归、仅匹配 script 关键字，且第 3 行关闭 X-XSS-Protection）。未发现 include/require、文件读写、SQL、命令执行、eval 等汇点，故无 LFI/RFI、命令注入、SQLi 链。未覆盖：php.ini 配置、部署路径、是否存在前置 WAF，均无法从 code_pack 判断。

未覆盖 / 证据缺口：
- 无 php.ini/服务器配置，无法判断 allow_url_include、open_basedir 等
- 无部署与访问路径信息，endpoints 为空
- 无依赖清单与历史提交

## 3. Findings

### F-1: 052.php 反射型 XSS：preg_replace 黑名单可被嵌套标签绕过

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`052.php:6-11`
- **来源**：`llm_finding`

**描述**

052.php 第 6 行从 $_GET['name'] 读取外部输入，第 8 行仅用正则 /<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i 删除形如 <...script...> 的子串，第 11 行将结果直接拼进 "<pre>Hello {$name}</pre>" 输出，未做 htmlspecialchars 等 HTML 实体编码。该黑名单只匹配一次、且要求 s-c-r-i-p-t 顺序出现，攻击者可用嵌套/拆分标签（如 <scr<script>ipt>alert(1)</script>，删除内层后外层重组为 <script>）或使用其它可执行标签（<img src=x onerror=...>、<svg onload=...>）绕过，构成反射型 XSS。第 3 行还主动发送 X-XSS-Protection: 0 关闭浏览器内置过滤器，进一步降低利用门槛。

**source / sink**

- source：query `name`（052.php）
- sink：052.php:11 echo/输出 $html，其中 $html .= "<pre>Hello {$name}</pre>"

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `052.php:6` | array_key_exists 检查 name 参数存在且非 NULL，攻击者可控 | 原始字符串 |  |
| 2 | `052.php:8` | preg_replace 用黑名单正则删除 <...script...> 子串，仅单次替换且不处理其它标签 | 过滤后字符串，仍含可执行 HTML | 黑名单只匹配 script 关键字且非递归替换，可用嵌套标签重组或改用 img/svg 等事件标签绕过 |
| 3 | `052.php:11` | 过滤结果直接拼入 HTML 并输出，无 HTML 实体编码 | 未编码 HTML 片段进入响应体 |  |

**POC**

针对 /052.php（GET）的反射型跨站脚本（CWE-79）POC。源码 052.php 第 11 行将 GET 参数 name 直接输出到响应，未做 HTML 编码，导致脚本在受害者浏览器执行。目标地址统一使用 TARGET 占位符。

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

反射型 XSS，可在受害者浏览器上下文执行任意 JS，窃取会话/发起 CSRF 式操作；因主动关闭 X-XSS-Protection，现代浏览器内置防护不生效。

**CVE / CWE 论证**

CWE-79。外部 GET 参数直达 HTML 输出，黑名单可绕过，无需认证，链闭合。

**修复建议**

输出前使用 htmlspecialchars($name, ENT_QUOTES, 'UTF-8') 编码；移除 X-XSS-Protection: 0；不要依赖黑名单正则过滤。

**验证说明**

需在真实浏览器/响应中确认嵌套标签重组后的实际输出与执行；不同 PHP 版本 preg_replace 行为一致，但需确认部署未额外加 WAF。
模型 POC 要点：向 name 参数注入可绕过黑名单的 XSS payload，观察响应中原样回显
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /052.php）：符合 CWE-79（跨站脚本）。漏洞位于 052.php 第 11 行，外部输入来自查询参数 name，source→sink 链在给定代码片段内静态闭合，未见有效输出编码或净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅保留文本工件，不执行、不联网。request.http 中的 Content-Length 与 GET 请求体不一致，实际 GET 无请求体，已按标准 GET 结构重写；poc.sh 仅作参考文本，禁止管线自动运行。若目标端口非 8080，需按实际部署调整 Host 中的端口。

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
| safety_guard | 安全防护 | 2.5 | 是 |
| surface_mapper | 攻击面测绘 | 7.02 | 是 |
| deep_finder | LLM 深挖 | 6.9 | 是 |
| candidate_screener | 候选筛选 | 2.83 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.62 | 是 |
| coordinator | 管线协调 | 5.92 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
