# 落日二号乙漏洞挖掘报告 — 20261031-214707-ce6cff

- 生成时间：2026-10-31T13:47:48.427401+00:00
- 输入：`$WORKSPACE\暴风星云裂\035.zip`
- 输入模式：`zip`
- SHA256：`26df21081a34ea6645ed0ec14c03a18413f379ea7d2f67f50d3952249217e9b6`
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

本次汇总仅包含 1 条已去重 finding：035.php 第 3 行读取 GET 参数 redirect，并在第 5 行将其用于重定向，构成开放重定向（open_redirect，medium，LLM-5ea158bc397a），已附带 POC（HTTP 型，可动态复现，仅限授权测试）。这是本次唯一交付项，也是最高危项；由于仓库仅 1 个 13 行 PHP 文件、无框架无路由，整体风险面很窄。POC 齐全度为 1/1，但全部为源码推断（llm_inferred），未经动态验证。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 310 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个文件 035.php（13 行）。已逐行审计：第 3 行读取 $_GET['redirect']，第 4 行直接拼入 header("location: ...")，构成闭合的开放重定向链（CWE-601），已作为 medium 报告。第 8 行 http_response_code(500) 与第 10 行静态文本无污点。未发现 SQL/命令/文件/反序列化/模板等 sink，也无认证、会话、加密、Cookie 证据，故无其它 finding。未覆盖范围：无路由/部署配置、无 php.ini、无依赖清单，无法确认实际 URL 与网关层是否另有校验；header 注入（CRLF）未主张，需动态确认。

未覆盖 / 证据缺口：
- 无部署/路由配置，无法确认 035.php 对外路径
- 无网关/WAF 配置，无法确认是否另有 redirect 校验
- 未验证 header 注入（CRLF）可行性

## 3. Findings

### F-1: 035.php 通过 GET 参数 redirect 造成开放重定向

- **类型**：`open_redirect` / CWE-601
- **严重度**：`medium`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`035.php:3-5`
- **来源**：`llm_finding`

**描述**

脚本在第 3 行用 array_key_exists("redirect", $_GET) 判断参数存在且非空，随后在第 4 行直接把 $_GET['redirect'] 拼进 header("location: " . ...) 并 exit。参数值未做任何白名单、域名校验或相对路径限制，攻击者可传入任意外部 URL，使服务端返回 302 跳转到攻击者站点，用于钓鱼、OAuth/SSO 令牌窃取或绕过基于域名的信任校验。

**source / sink**

- source：query `redirect`（035.php:3）
- sink：035.php:5 header("location: " . $_GET['redirect']) 响应头写入

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `035.php:3` | 读取 GET 参数 redirect，仅校验存在且非空 | 攻击者完全可控的字符串，未过滤 |  |
| 2 | `035.php:4` | 将参数值直接拼接进 location 响应头并发送 | 原样进入 HTTP Location 头 | 无任何域名/协议白名单或相对路径校验，!= "" 仅排除空串 |

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
- POC 目录：`poc/LLM-5ea158bc397a`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可构造指向自身站点的可信域名链接，诱导用户点击后跳转至钓鱼页面，或配合 OAuth/登录回调窃取凭据；也可用于绕过依赖跳转域名的访问控制。

**CVE / CWE 论证**

CWE-601 URL Redirection to Untrusted Site。外部无需认证即可通过 GET 参数触发，source→sink 链在 035.php:3-4 完整闭合，无过滤。

**修复建议**

对 redirect 目标做严格白名单（仅允许本站相对路径或预置可信域名），拒绝含协议/双斜杠的绝对 URL，或改用服务端映射的跳转标识。

**验证说明**

需确认 035.php 实际部署路径与是否被网关层拦截；header 注入（CRLF）在多数 PHP 版本会被拦截，本报告仅主张开放重定向。
模型 POC 要点：请求带 redirect 参数的 URL，服务端返回 302 跳转到外部站点
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /035.php）：针对 035.php（GET）的开放重定向 POC。注入点为 GET 参数 redirect，该参数被直接用于跳转目标（035.php:5），未做白名单或同源校验；payload 使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /035.php）：符合 CWE-601（URL 重定向到不可信站点）。漏洞位于可交付代码 035.php:5，外部输入来自 query 参数 redirect，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标，并手动检查响应中的 Location 头。

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
| safety_guard | 安全防护 | 4.95 | 是 |
| surface_mapper | 攻击面测绘 | 6.2 | 是 |
| deep_finder | LLM 深挖 | 7.09 | 是 |
| candidate_screener | 候选筛选 | 3.3 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.56 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.11 | 是 |
| coordinator | 管线协调 | 6.0 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
