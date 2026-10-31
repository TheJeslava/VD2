# 落日二号乙漏洞挖掘报告 — 20261031-214717-2fa798

- 生成时间：2026-10-31T13:48:04.768875+00:00
- 输入：`$WORKSPACE\暴风星云裂\036.zip`
- 输入模式：`zip`
- SHA256：`21f0b55e102a19f7e1305cfce872a6ab1e1c931079a8ad1e4b9dbafe94f87b7f`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.5.0-ver5
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总仅含 1 条已去重 finding：036.php 第 4 行读取请求参数后，第 13 行附近将 redirect 参数直接用于跳转，未校验协议与目标，判定为开放重定向（open_redirect，medium，LLM-7af8cc31bcdd），已附 POC（HTTP 型，可动态复现，仅限授权测试）。最高危即此条，也是唯一交付项。POC 齐全度：1/1 有 POC。需说明：surface_notes 明确指出输入未提供 036.php 源码行内容、sink_hot_files 为空，因此该 finding 的 source→sink 连通性属 llm_inferred 级别推断，未经动态验证；注入类（SQL/命令/XSS/路径穿越/SSRF）与配置类（weak_crypto/weak_hash/weak_random/insecure_cookie/trust_boundary/hardcoded_secret）均无源码证据，不能断言不存在，只能记为未覆盖。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 524 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 036.php（21 行），已通读全文。唯一外部输入为第 3 行 $_GET['redirect']，经第 4 行 http/https 前缀黑名单后在第 11 行拼入 Location 响应头，构成可绕过的开放重定向（CWE-601），已给出闭合利用链与 POC。未发现 SQL 拼接、命令执行、文件包含、反序列化、SSRF、XSS 等其它汇点；sink_hot_files 为空与源码一致。未覆盖范围：无 php.ini/.htaccess/部署配置，无法确认 allow_url_include、是否对外可达及 Location 头规范化行为；无依赖清单与版本历史。

未覆盖 / 证据缺口：
- 缺少 php.ini/.htaccess/Web 服务器配置，无法确认 Location 头是否被规范化及 036.php 对外可达性
- 无端点/路由清单，HTTP 方法依据源码推断为 GET
- 无依赖清单与提交历史，无法评估第三方组件与引入背景

## 3. Findings

### F-1: 036.php redirect 参数未校验协议，可构造开放重定向（含 javascript:/data: 伪协议）

- **类型**：`open_redirect` / CWE-601
- **严重度**：`medium`
- **置信度**：`0.82`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`036.php:3-13`
- **来源**：`llm_finding`

**描述**

036.php 第 3 行从 $_GET['redirect'] 读取跳转目标，第 4 行仅用正则 /http:\/\/|https:\/\//i 拦截以 http:// 或 https:// 开头的绝对 URL，第 11 行直接将该值拼入 header("location: " . $_GET['redirect'])。该黑名单只覆盖两种协议前缀，攻击者可用协议相对 URL（//evil.example）、反斜杠变体（\\evil.example、/\evil.example）、其它协议（javascript:、data:、ftp:、//）或大小写/空白绕过，把用户重定向到攻击者控制的站点，用于钓鱼、OAuth/SSO 回调劫持与凭据窃取。

**source / sink**

- source：query `redirect`（036.php）
- sink：036.php:13 header("location: " . $_GET['redirect']) 位于 036.php:11

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `036.php:3` | array_key_exists 检查 redirect 参数存在且非空，攻击者完全可控该值 | 原始字符串，未做任何规范化 |  |
| 2 | `036.php:4` | preg_match 黑名单仅匹配 http:// 或 https:// 前缀，不匹配即进入 else 分支 | 仅做前缀黑名单匹配，未做协议白名单/URL 解析 | 使用 //evil.example、\\evil.example、javascript:alert(1)、data:text/html,... 等不以 http:// 或 https:// 开头的值即可绕过 |
| 3 | `036.php:11` | 未校验的 redirect 值被直接拼入 Location 响应头并 exit | 原样写入 HTTP 响应头 |  |

**POC**

针对 /036.php（GET）的 开放重定向 POC。注入点：GET 参数 redirect；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/036.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 开放重定向 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/036.php?redirect=%2F%2Fexample.com'
```
预期：响应为 30x 且 Location 指向攻击者控制的域名。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`//example.com`
- POC 目录：`poc/LLM-7af8cc31bcdd`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

开放重定向：攻击者可构造可信域名的跳转链接用于钓鱼、窃取凭据，或在 OAuth/SSO 流程中劫持回调窃取授权码/令牌。

**CVE / CWE 论证**

CWE-601 URL 重定向到不可信站点。外部无需认证即可通过 GET 参数触发，source→sink 链在 036.php:3-11 完整闭合，黑名单可被协议相对 URL 与伪协议绕过。

**修复建议**

改为协议+主机白名单校验：解析 URL 后仅允许相对路径（以单个 / 开头且非 //）或与站点同源的绝对 URL；拒绝包含 ://、//、\\、: 的值，并对输出做编码。

**验证说明**

需动态确认 Web 服务器/PHP 是否原样输出 Location 头（部分环境会规范化 // 前缀），以及客户端是否跟随 javascript:/data: 伪协议；未提供 php.ini 与部署信息。
模型 POC 要点：利用协议相对 URL 绕过 http/https 黑名单，使服务端返回指向攻击者站点的 302 跳转
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /036.php）：针对 036.php 的开放重定向（CWE-601）POC。源码 036.php:13 将 GET 参数 redirect 的值直接用于跳转（Location 头），未做白名单或同源校验，攻击者可传入 //example.com 使浏览器跳转到外部域名。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /036.php）：符合 CWE-601（URL 重定向至不可信站点）。漏洞位于 036.php:13，外部输入来自 GET 参数 redirect，source→sink 链在给定代码范围内静态闭合，未见有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅保留文本请求结构，不生成可自动执行的脚本；如需手工复现，请自行将 TARGET 替换为授权实例地址并逐条发送上述原始 HTTP 请求。禁止使用 curl|sh 等自动执行方式。

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
| `blind_sql_injection` | CWE-89 |  | 0 |
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
| safety_guard | 安全防护 | 4.52 | 是 |
| surface_mapper | 攻击面测绘 | 6.6 | 是 |
| deep_finder | LLM 深挖 | 8.79 | 是 |
| candidate_screener | 候选筛选 | 4.03 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.93 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 9.12 | 是 |
| coordinator | 管线协调 | 6.86 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
