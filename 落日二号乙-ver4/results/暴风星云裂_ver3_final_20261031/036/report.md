# 落日二号乙漏洞挖掘报告 — 20261031-014216-eb0663

- 生成时间：2026-10-30T17:42:54.361683+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\036.zip`
- 输入模式：`zip`
- SHA256：`21f0b55e102a19f7e1305cfce872a6ab1e1c931079a8ad1e4b9dbafe94f87b7f`
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

本次汇总仅含 1 条已去重 finding：036.php 的 open_redirect（medium，LLM-7af8cc31bcdd），声称 redirect 参数黑名单可绕过并注入 header Location，已附 POC（静态文本 POC，未动态验证）。最高危即该条 medium 开放重定向。POC 齐全度：1/1 finding 带 POC，但均为源码推断级（llm_inferred），无任何动态验证。整体覆盖极薄：仅 1 个 PHP 文件、21 行、0 个已识别端点、无框架、无配置、无依赖清单，sink_hot_files 为空，source→sink 数据流未闭合，因此除该条外不能对注入类、文件包含、XSS 等作任何结论。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 524 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 036.php（21 行，已全量展示）。确认 036.php:3 的 $_GET['redirect'] 经 036.php:4 的弱黑名单后于 036.php:11 直接进入 header Location，构成可绕过的开放重定向（CWE-601）。未发现 SQL/命令/文件包含/反序列化等 sink；无 md5/sha1/rand/setcookie 等弱实现证据，故 weak_hash/weak_crypto/weak_random/insecure_cookie 均无候选。code_pack 之外无其它文件，未覆盖部署配置、php.ini、依赖清单与真实路由。

未覆盖 / 证据缺口：
- 无 php.ini/Web 服务器配置，无法判断 header() 对 CRLF 的处理与 allow_url_include 等
- 无真实路由与参数清单，endpoint 按文件名推断为 /036.php
- 无依赖清单，未评估第三方组件 CVE
- 无认证/会话证据，trust_boundary 与 insecure_cookie 无法评估

## 3. Findings

### F-1: 036.php redirect 参数黑名单可绕过导致开放重定向（header Location 注入）

- **类型**：`open_redirect` / CWE-601
- **严重度**：`medium`
- **置信度**：`0.82`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`036.php:3-13`
- **来源**：`llm_finding`

**描述**

036.php 第 3 行从 $_GET['redirect'] 读取外部输入，第 4 行仅用正则 /http:\/\/|https:\/\//i 做黑名单过滤，第 11 行把原始输入直接拼进 header("location: " . $_GET['redirect'])。该黑名单只拦截以 http:// 或 https:// 开头的绝对 URL，未做协议白名单、未校验是否以 / 开头、未做规范化。攻击者可构造 //evil.example、/\evil.example、https:evil.example（无斜杠）、以及含 CRLF 的载荷绕过过滤，使服务端返回 302 跳转到攻击者控制的站点，或通过 header 注入注入额外响应头。

**source / sink**

- source：query `redirect`（036.php:3）
- sink：036.php:13 header("location: " . $_GET['redirect']) 位于 036.php:11

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `036.php:3` | 从 $_GET['redirect'] 读取外部输入，仅要求非空 | 原始攻击者字符串 |  |
| 2 | `036.php:4` | preg_match 黑名单只匹配 http:// 或 https:// 前缀 | 未匹配则进入 else 分支 | //evil.example、https:evil.example、/\evil.example 均不含 http:// 或 https:// 字面量，正则不命中 |
| 3 | `036.php:11` | 未做任何编码或校验，直接拼入 Location 响应头 | 原样进入 HTTP 响应头 | 无协议白名单、无前导 / 校验、无 CRLF 过滤 |

**POC**

针对 /036.php（GET）的开放重定向（CWE-601）POC。注入点为 GET 参数 redirect，其值被直接用于跳转目标（036.php:13 附近），未做白名单或同源校验。payload 使用 //example.com 形式，浏览器会将其解析为协议相对的外部主机。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/036.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 开放重定向 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/036.php?redirect=%2F%2Fexample.com'
```
预期：响应 30x 且 Location 指向攻击者控制的域名。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`//example.com`
- POC 目录：`poc/LLM-7af8cc31bcdd`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可构造可信域名的钓鱼链接，诱导用户跳转到恶意站点窃取凭据；若 CRLF 注入可行还可设置 Cookie 或缓存投毒。

**CVE / CWE 论证**

CWE-601 开放重定向。外部无需认证即可通过 GET 参数触发，黑名单可被协议相对 URL 绕过，链闭合。

**修复建议**

改为白名单校验：仅允许以单个 / 开头且不含 // 和 \ 的相对路径，或使用允许域名列表比对；对输出做 urlencode 并拒绝含 CR/LF 的输入。

**验证说明**

需确认目标 PHP 版本对 header() 中 CRLF 的处理；协议相对 URL 绕过在任意版本均成立，可直接动态验证 302 Location 值。
模型 POC 要点：利用协议相对 URL 或缺失斜杠的 scheme 绕过黑名单，实现跳转到外部站点
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /036.php）：符合 CWE-601（URL 重定向至不可信站点）。漏洞位于 036.php:13，外部输入来自 query 参数 redirect，source→sink 链静态闭合，未见有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须替换 TARGET 为授权测试主机并确认授权范围。建议同时用 -L 关闭自动跟随（curl 默认不跟随），以便观察原始 30x 与 Location 头。若目标返回 200 而非 30x，需检查是否为 JS/meta 跳转形式，并相应调整预期响应描述。

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
| safety_guard | 安全防护 | 2.57 | 是 |
| surface_mapper | 攻击面测绘 | 7.16 | 是 |
| deep_finder | LLM 深挖 | 7.18 | 是 |
| candidate_screener | 候选筛选 | 2.81 | 是 |
| vulnerability_analyzer | 漏洞分析 | 4.66 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.93 | 是 |
| coordinator | 管线协调 | 6.0 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
