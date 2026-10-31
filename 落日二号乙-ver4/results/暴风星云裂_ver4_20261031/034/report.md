# 落日二号乙漏洞挖掘报告 — 20261031-164454-909022

- 生成时间：2026-10-31T08:45:37.148709+00:00
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

本次汇总仅包含 1 条已去重 finding：034.php 的开放重定向（open_redirect，medium，LLM-347c957364bd），基于 redirect 参数与 strpos 子串校验的绕过逻辑，已附带 POC（HTTP 型，可动态复现方向明确，但本次未执行验证）。最高危即该条 medium 开放重定向，无高危/严重项。POC 齐全度为 1/1（with_poc=1）。需强调：本次输入未提供 034.php 源码正文，仅有文件元数据与热点行号（source 热点 034.php:4，sink_hot_files 为空），因此除该条 finding 外，其余攻击面判断均为范围测绘，不构成漏洞结论；sink_hot_files 为空不代表不存在危险汇点。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 527 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 034.php（21 行），已逐行审计。确认一条闭合链：GET 参数 redirect 经 strpos 子串包含校验（034.php:4）后直接进入 header("location: ...")（034.php:5），构成开放重定向（CWE-601），POC 可构造。未发现命令执行、SQL、文件包含、反序列化等 sink；脚本无 session/cookie/md5 等调用，故 surface_notes 中 insecure_cookie、weak_hash、trust_boundary 三项无源码证据支撑，不单独立项。未覆盖范围：无 Web 服务器/php.ini/路由配置，无法确认可达性、错误显示与代理行为；无依赖清单，无法评估第三方组件。

未覆盖 / 证据缺口：
- 缺少部署与 Web 服务器配置，无法确认 034.php 的实际可达路径与 Location 头是否被代理改写
- 无 php.ini/错误显示配置，无法评估信息泄露
- 无依赖清单，未评估第三方组件 CVE
- surface_notes 提到的 insecure_cookie/weak_hash 在源码中无对应调用，无法确认或排除

## 3. Findings

### F-1: 034.php 通过 redirect 参数与 strpos 子串校验实现开放重定向

- **类型**：`open_redirect` / CWE-601
- **严重度**：`medium`
- **置信度**：`0.82`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`034.php:3-6`
- **来源**：`llm_finding`

**描述**

脚本从 $_GET['redirect'] 读取跳转目标，仅用 strpos($_GET['redirect'], "info.php") !== false 判断参数值中是否“包含”子串 info.php，随后直接拼接到 header("location: " . $_GET['redirect'])。由于校验是子串包含而非严格白名单/同源校验，攻击者可构造同时包含 info.php 与外部地址的值（如 //evil.example/info.php 或 https://evil.example/info.php），使 Location 头指向攻击者控制域，形成开放重定向，可用于钓鱼、OAuth/SSO 令牌窃取与信任链滥用。

**source / sink**

- source：query `redirect`（034.php:3）
- sink：034.php:6 header("location: " . $_GET['redirect']) 位于 034.php:5

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `034.php:3` | 读取 GET 参数 redirect，仅校验非空 | 原始攻击者字符串，未解码未过滤 |  |
| 2 | `034.php:4` | strpos 判断参数值是否包含子串 info.php，属于子串包含校验而非白名单/同源校验 | 仍为原始字符串，只要包含 info.php 即通过 | 校验只要求包含 info.php，攻击者可在外部 URL 路径或查询串中放入 info.php 通过校验 |
| 3 | `034.php:5` | 通过校验后直接拼接进 Location 响应头并跳转 | 攻击者完全可控的 URL 写入 Location 头 | 无域名白名单、无相对路径限制、无 scheme/host 校验 |

**POC**

针对 /034.php（GET）的 开放重定向 POC。注入点：GET 参数 redirect；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/034.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 开放重定向 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/034.php?redirect=%2F%2Fexample.com'
```
预期：响应为 30x 且 Location 指向攻击者控制的域名。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`//example.com`
- POC 目录：`poc/LLM-347c957364bd`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可借助受信任域名的跳转链接实施钓鱼、窃取 Referer/令牌、配合 OAuth 回调劫持授权码，降低受害者警惕。

**CVE / CWE 论证**

CWE-601 URL 重定向到不可信站点。外部无需认证即可通过 GET 参数触发，校验为子串包含可被轻易绕过，链路在 034.php:3-6 内闭合。

**修复建议**

不要直接使用用户输入作为 Location；改为固定映射表（如仅允许 info 对应 /info.php），或解析 URL 后严格校验 host 与 scheme 属于白名单，并拒绝 // 开头与绝对外部地址。

**验证说明**

需动态确认 Web 服务器是否原样透传 Location 头、是否存在前置 WAF 或反向代理改写；header() 在已有输出时会失败，需确认脚本无前置输出。
模型 POC 要点：构造同时包含 info.php 子串的外部地址，使服务端返回指向攻击者域的 302 跳转
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /034.php）：针对 034.php 第 6 行的开放重定向（CWE-601）POC。注入点为 GET 查询参数 redirect，其值被直接用于跳转目标，未做白名单或同源校验；payload 使用 //example.com 触发协议相对跳转。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /034.php）：符合 CWE-601（URL 重定向到不可信站点）。漏洞位于可交付代码 034.php:6，外部输入来自查询参数 redirect，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅保留文本工件，不执行、不联网。poc.sh 与 request.http 中的 TARGET 需由授权测试人员替换为实际测试主机；执行前须确认授权范围。request.http 中 Content-Length 仅对带 body 的请求有意义，本 GET 请求无 body，可忽略该头。

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
| safety_guard | 安全防护 | 4.51 | 是 |
| surface_mapper | 攻击面测绘 | 7.07 | 是 |
| deep_finder | LLM 深挖 | 7.61 | 是 |
| candidate_screener | 候选筛选 | 3.31 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.67 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.67 | 是 |
| coordinator | 管线协调 | 4.89 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
