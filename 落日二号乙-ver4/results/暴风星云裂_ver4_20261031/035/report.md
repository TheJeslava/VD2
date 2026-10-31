# 落日二号乙漏洞挖掘报告 — 20261031-164515-bd4cc2

- 生成时间：2026-10-31T08:45:56.506896+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\035.zip`
- 输入模式：`zip`
- SHA256：`26df21081a34ea6645ed0ec14c03a18413f379ea7d2f67f50d3952249217e9b6`
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

本次审计范围极小：仅 1 个 PHP 单文件 035.php（13 行），无框架、无路由配置、无已登记 HTTP 端点。去重后仅交付 1 条 finding：LLM-17fe713500f4，类型 open_redirect（medium），位于 035.php 第 3–4 行，redirect 参数未校验即写入 Location 头；该条已附带 POC（HTTP 型，可动态复现，目标以 TARGET 占位，仅限授权测试）。最高危即此条开放重定向，可用于钓鱼跳转与 OAuth/回调链滥用。POC 齐全度：1/1 已交付 finding 均有 POC，无缺失。需强调：本次未交付注入类（SQL/命令/路径遍历/XSS）与配置型（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）结论，原因是攻击面测绘显示 source 热点在 035.php:3 而 sink 热点为空，且无对应候选产出，属覆盖不足而非已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 310 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 035.php（13 行），已逐行审计。第 3 行读取 $_GET['redirect']，第 4 行未做任何校验直接写入 Location 响应头，构成开放重定向（CWE-601），链完整闭合。文件中未出现 md5/sha1/rand/mt_rand/setcookie/文件操作/命令执行/SQL/反序列化/模板等调用，故 weak_hash、weak_crypto、weak_random、insecure_cookie、trust_boundary、path_traversal、command_injection、sql_injection、xss 等候选均无源码证据，不报告。未覆盖范围：无 composer.json、无框架/服务器配置、无端点清单，无法确认实际部署路径与是否存在中间层校验；这些缺口已写入 coverage.gaps。

未覆盖 / 证据缺口：
- 无部署配置（.htaccess/nginx），无法确认 URL 映射与中间层是否限制 Location
- 无端点清单，实际可访问路径需人工确认
- 无依赖版本信息，无法评估第三方组件 CVE
- 未提供运行时上下文，无法确认是否存在日志/数据库等二次注入场景

## 3. Findings

### F-1: 035.php 通过 redirect 参数未校验即写入 Location 头导致开放重定向

- **类型**：`open_redirect` / CWE-601
- **严重度**：`medium`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`035.php:3-4`
- **来源**：`llm_finding`

**描述**

脚本在第 3 行读取 $_GET['redirect']，仅判断其存在且非空字符串，随后在第 4 行直接拼接进 header("location: " . $_GET['redirect'])。没有任何白名单、同源校验、scheme 过滤或相对路径限制，攻击者可传入任意外部 URL（如 https://evil.example/），使服务端返回 302 跳转到攻击者站点。可用于钓鱼、OAuth/SSO 回调令牌窃取、绕过基于域名的信任检查。

**source / sink**

- source：query `redirect`（035.php:3）
- sink：035.php:4 header("location: " . $_GET['redirect']) 响应头写入

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `035.php:3` | 从 $_GET 读取 redirect 参数，仅做存在性与非空判断 | 攻击者完全可控的字符串，未做任何过滤 |  |
| 2 | `035.php:4` | 将参数原样拼接到 Location 响应头并发送 302 | 原样拼接进 header，无白名单/同源校验 | 仅校验 != ""，不限制 scheme、host 或路径，外部绝对 URL 直接通过 |

**POC**

针对 /035.php（GET）的 开放重定向 POC。注入点：GET 参数 redirect；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/035.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 开放重定向 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/035.php?redirect=%2F%2Fexample.com'
```
预期：响应为 30x 且 Location 指向攻击者控制的域名。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`//example.com`
- POC 目录：`poc/LLM-17fe713500f4`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可借助受信任域名的跳转链接实施钓鱼、窃取 OAuth/SSO 授权码或令牌、绕过依赖域名白名单的安全校验。

**CVE / CWE 论证**

CWE-601 URL 重定向到不可信站点。外部无需认证即可通过 GET 参数触发，source→sink 链在 035.php:3-4 完整闭合，无任何校验环节。

**修复建议**

对 redirect 目标做白名单或同源校验：仅允许相对路径（拒绝含 :// 或 // 的值），或与预置的允许跳转列表比对后再写入 Location。

**验证说明**

需动态确认 Web 服务器未在中间层对 Location 做额外限制，以及 PHP 未开启会阻止 header 跳转的配置；源码层面链已闭合。
模型 POC 要点：构造 redirect 指向外部攻击者域名，观察服务端返回 302 且 Location 为外部地址
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /035.php）：针对 035.php 第 4 行的开放重定向（CWE-601）。源码从 GET 参数 redirect 读取外部输入并直接用于跳转（Location 头），未做白名单或同源校验，攻击者可构造指向外部站点的跳转链接用于钓鱼。POC 仅使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /035.php）：漏洞位于 035.php:4，外部输入来自 GET 参数 redirect，source→sink 链在给定代码片段内静态闭合，未见有效净化或目标白名单，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。执行时需将 TARGET 替换为授权测试实例地址；判定依据为响应头 Location 是否指向外部域名。

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
| `open_redirect` | CWE-601 |  | 1 |
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
| safety_guard | 安全防护 | 3.78 | 是 |
| surface_mapper | 攻击面测绘 | 8.31 | 是 |
| deep_finder | LLM 深挖 | 6.54 | 是 |
| candidate_screener | 候选筛选 | 2.45 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.17 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.86 | 是 |
| coordinator | 管线协调 | 7.63 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
