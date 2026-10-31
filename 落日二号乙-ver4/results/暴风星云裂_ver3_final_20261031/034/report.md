# 落日二号乙漏洞挖掘报告 — 20261031-014154-45992b

- 生成时间：2026-10-30T17:42:30.888928+00:00
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

本次汇总仅包含 1 条已去重发现：034.php 第 4 行接收外部输入，第 6 行通过 redirect 参数与 strpos 子串校验实现开放重定向（open_redirect，medium，LLM-347c957364bd），已附带 POC，属 HTTP 类可复现工件（未执行、未动态验证）。最高危即该条 medium 开放重定向：校验仅判断参数中是否包含受信子串，攻击者可构造形如 TARGET 前缀的跳转地址绕过。POC 齐全度：1/1 有 POC，但仅为静态文本工件，未经动态确认。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 527 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 034.php（21 行），已全量审计。第 3-6 行存在开放重定向：$_GET['redirect'] 经 strpos 子串校验后直接进入 header('location: ...')，可用 https://attacker/info.php 或 //attacker/info.php 绕过。未发现命令执行、SQL、文件读写、反序列化、include 等其它 sink；文件中无 md5/sha1/rand/setcookie 等弱实现或会话配置，故未报告 weak_hash/weak_crypto/weak_random/insecure_cookie。未覆盖范围：无 php.ini、Web 服务器配置、路由与认证信息，无法判断是否存在前置鉴权或 URL 重写；端点表为空，入口按直接访问 034.php 推断。

未覆盖 / 证据缺口：
- 缺少 Web 服务器与 php.ini 配置，无法确认 header 注入过滤与部署路径
- 无端点清单，参数名与请求方法按源码推断
- 无依赖清单，未评估第三方组件

## 3. Findings

### F-1: 034.php 通过 redirect 参数与 strpos 子串校验实现开放重定向

- **类型**：`open_redirect` / CWE-601
- **严重度**：`medium`
- **置信度**：`0.82`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`034.php:3-6`
- **来源**：`llm_finding`

**描述**

脚本从 $_GET['redirect'] 读取目标地址，仅用 strpos($_GET['redirect'], "info.php") !== false 判断子串是否出现，随后直接 header("location: " . $_GET['redirect']) 跳转。校验只要求 URL 任意位置包含子串 info.php，未做协议/主机白名单、未用 parse_url 校验 host、未强制相对路径，因此攻击者可构造 https://attacker/info.php 或 //attacker/info.php 等外部地址通过校验，实现开放重定向，可用于钓鱼、OAuth token 窃取、绕过 SSRF 白名单等。

**source / sink**

- source：query `redirect`（034.php:3）
- sink：034.php:6 header("location: " . $_GET['redirect']) 位于 034.php:5

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `034.php:3` | 从 $_GET['redirect'] 读取外部可控参数，仅判断非空 | 原始字符串，未过滤 |  |
| 2 | `034.php:4` | strpos 检查子串 info.php 是否出现，任意位置出现即通过 | 仅做子串包含判断，未规范化、未校验 host/scheme | 把 info.php 放在路径或查询串中即可满足 strpos，例如 https://attacker.example/info.php |
| 3 | `034.php:5` | 将未校验的 redirect 直接拼入 Location 响应头并跳转 | 原样进入 HTTP 响应头 |  |

**POC**

针对 /034.php（GET）的开放重定向 POC。注入点为 GET 参数 redirect，源码 034.php:6 将外部输入直接用于跳转目标，未做白名单或同源校验；payload 使用 TARGET 占位符，仅限授权测试。

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
- POC 目录：`poc/LLM-347c957364bd`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可借助受信任域名构造钓鱼链接、窃取 OAuth/SSO 回调中的令牌或绕过下游基于域名的白名单校验。

**CVE / CWE 论证**

CWE-601 URL 重定向到不可信站点。外部 GET 参数直达 Location 头，校验仅为子串包含，链闭合，无需认证。

**修复建议**

使用 parse_url 校验 scheme 与 host 白名单，或仅允许固定的相对路径（如 /info.php），拒绝包含 :// 或 // 开头的值；不要用子串包含作为安全判断。

**验证说明**

需确认 Web 服务器/PHP 是否对 header 中的换行做过滤（现代 PHP 会阻止 CRLF 注入），以及实际部署路径；开放重定向本身不依赖运行时特殊条件。
模型 POC 要点：构造包含 info.php 子串的外部 URL，使服务端返回 302 跳转到攻击者站点
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /034.php）：符合 CWE-601（URL 重定向到不可信站点）。漏洞位于可交付代码 034.php:6，外部输入来自 query 参数 redirect，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前将 TARGET 替换为授权测试目标；curl 命令仅供人工在授权环境手动运行，禁止自动化批量投递。

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
| safety_guard | 安全防护 | 2.42 | 是 |
| surface_mapper | 攻击面测绘 | 6.56 | 是 |
| deep_finder | LLM 深挖 | 7.69 | 是 |
| candidate_screener | 候选筛选 | 2.65 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.2 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.8 | 是 |
| coordinator | 管线协调 | 5.57 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
