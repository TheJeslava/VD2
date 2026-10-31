# 落日二号乙漏洞挖掘报告 — 20261031-011947-7faeb8

- 生成时间：2026-10-30T17:20:24.744093+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\034.zip`
- 输入模式：`zip`
- SHA256：`017f433a8e9090aa42467f885f1acd0bb69513cfebb57a3bf352d9244a244cd9`
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

本次汇总仅含 1 条已去重 finding：034.php 第 4-5 行的开放重定向（open_redirect，medium，LLM-b2053a861f4e），成因是 redirect 参数用 strpos 做子串匹配校验，可被构造 URL 绕过；该条已附带 POC（HTTP 型，可动态复现，仅限授权测试）。最高危即此条 medium，无高危/严重项。POC 齐全度：1/1 已具备。需强调：本次仅覆盖 1 个 PHP 文件、0 个端点，且 surface_notes 明确说明未提供 034.php 代码正文，攻击面测绘基于清单元数据推断，因此“无其他类型”只是当前证据下的交付状态，不等于已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 527 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 034.php（21 行），已逐行审计。第 3-5 行构成完整的 source（$_GET['redirect']）→ 弱校验（strpos 子串匹配）→ sink（header Location）链路，判定为开放重定向（CWE-601），置信度 0.82。文件中未发现 SQL/命令/文件包含/反序列化/eval 等其它高危构造；第 9-11、17-18 行的静态 HTML 输出不含用户输入，无 XSS。surface_notes 中提到的 weak_crypto/weak_hash/insecure_cookie 等配置类线索在代码中无对应实现，不成立。未覆盖范围：无路由/部署配置，无法确认该脚本是否被其它文件包含或是否有前置网关校验；无 composer 依赖，未评估第三方组件。

未覆盖 / 证据缺口：
- 无部署配置（php.ini、Web 服务器规则），无法确认 header() 输出是否被网关改写
- 无路由/包含关系信息，无法确认 034.php 的实际暴露路径与是否有上游校验
- 无依赖清单，未评估第三方组件 CVE

## 3. Findings

### F-1: 034.php redirect 参数校验缺陷导致开放重定向（strpos 子串匹配可绕过）

- **类型**：`open_redirect` / CWE-601
- **严重度**：`medium`
- **置信度**：`0.82`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`034.php:3-5`
- **来源**：`llm_finding`

**描述**

034.php 第 3 行从 $_GET['redirect'] 读取外部输入，第 4 行仅用 strpos($_GET['redirect'], "info.php") !== false 做子串包含判断，第 5 行直接把原始输入拼进 header("location: " . $_GET['redirect'])。由于校验只要求字符串中任意位置出现 info.php，攻击者可构造 https://evil.example/info.php 或 //evil.example/info.php 之类的外部 URL 通过校验，从而把用户重定向到攻击者控制的站点，用于钓鱼或 OAuth/SSO 场景下的令牌窃取。

**source / sink**

- source：query `redirect`（034.php:3）
- sink：034.php:5 header("location: " . $_GET['redirect']) 位于 034.php:5

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `034.php:3` | 从 $_GET['redirect'] 读取外部输入，仅判断非空 | 原始攻击者字符串 |  |
| 2 | `034.php:4` | strpos 子串包含校验，只要求出现 info.php，不校验 scheme/host/是否以 / 开头 | 含 info.php 子串的任意 URL | 子串匹配而非前缀/白名单匹配，https://evil.example/info.php 或 //evil.example/info.php 均满足 strpos !== false |
| 3 | `034.php:5` | 未做任何规范化或域名白名单，直接拼入 Location 响应头 | 攻击者控制的绝对/协议相对 URL 写入 Location 头 |  |

**POC**

针对 /034.php（GET）的开放重定向 POC。注入点为 GET 参数 redirect，源码 034.php:5 将该参数直接用于跳转（Location/header 重定向），未做白名单或同源校验。payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/034.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 开放重定向 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/034.php?redirect=%2F%2Fexample.com'
```
预期：响应 30x 且 Location 指向攻击者控制的域名。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`//example.com`
- POC 目录：`poc/LLM-b2053a861f4e`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可构造可信域链接诱导用户跳转到钓鱼站点，或在 OAuth/SSO 回调场景中窃取授权码/令牌，造成账户接管风险。

**CVE / CWE 论证**

CWE-601 URL 重定向到不可信站点。外部无需认证即可通过 GET 参数触发，source→sink 链在 034.php:3-5 完整闭合，校验逻辑（strpos 子串匹配）可被外部 URL 直接绕过。

**修复建议**

不要直接使用用户输入作为 Location。改为白名单映射（如只允许固定相对路径 /info.php），或解析 URL 后校验 host 与 scheme 属于本站，并强制以 / 开头的站内相对路径。

**验证说明**

需动态确认 Web 服务器/PHP 是否原样输出 Location 头（header() 对含换行的输入会报错，但普通 URL 可正常输出）；需确认是否存在上游网关对 redirect 参数做二次校验。
模型 POC 要点：利用 strpos 子串匹配缺陷，把 redirect 设为包含 info.php 的外部 URL，使服务端返回指向攻击者站点的 302
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /034.php）：符合 CWE-601（URL 重定向到不可信站点）。漏洞位于可交付代码 034.php:5，外部输入来自 query 参数 redirect，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前将 TARGET 替换为授权测试目标；request.http 中 Content-Length 仅对带 body 的请求有意义，GET 无 body 时可忽略。

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
| safety_guard | 安全防护 | 2.54 | 是 |
| surface_mapper | 攻击面测绘 | 7.02 | 是 |
| deep_finder | LLM 深挖 | 7.19 | 是 |
| candidate_screener | 候选筛选 | 2.58 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.9 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.17 | 是 |
| coordinator | 管线协调 | 5.69 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
