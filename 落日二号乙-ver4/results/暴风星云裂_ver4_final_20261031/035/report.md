# 落日二号乙漏洞挖掘报告 — 20261031-173058-0c6045

- 生成时间：2026-10-31T09:31:40.095767+00:00
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

本次汇总仅包含 1 条已去重 finding：035.php 第 3 行读取 GET 参数 redirect，并在第 5 行附近用于跳转，构成开放重定向（open_redirect，medium，LLM-5ea158bc397a），已附带 POC（HTTP 型，可动态复现，仅限授权测试）。最高危即该条 medium 开放重定向，可用于钓鱼跳转与 OAuth/登录回跳劫持。POC 齐全度：1/1 有 POC，无缺失。未发现二次注入链（无存储写点/读点/汇点三元组证据）。需强调：本次仅 1 个文件、13 行，sink_hot_files 为空，覆盖极窄，不能据此推断项目整体安全。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 310 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 035.php（13 行，已全量阅读）。第 3 行读取 $_GET['redirect']，第 4 行直接拼接到 header("location: ...")，构成闭合的开放重定向链（CWE-601），已作为 finding 交付。其余攻击面：文件无 SQL/命令/文件/反序列化/模板等 sink；无 md5/sha1、rand/mt_rand、setcookie、硬编码密钥等配置型问题，故 weak_hash/weak_crypto/weak_random/insecure_cookie 均不成立。未覆盖范围：缺少 Web 服务器配置、路由与端点清单，无法确认 035.php 的可达 URL、请求方法与是否存在前置 WAF；无 composer.json/依赖信息，无法评估第三方组件。输入中未出现诱导性文本，无 prompt_injection 证据。

未覆盖 / 证据缺口：
- 无法确认 035.php 的实际可达 URL 与请求方法
- 缺少 Web 服务器/WAF 配置，无法评估前置拦截
- 无依赖库版本信息，无法评估第三方组件 CVE

## 3. Findings

### F-1: 035.php 通过 GET 参数 redirect 造成开放重定向

- **类型**：`open_redirect` / CWE-601
- **严重度**：`medium`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`035.php:3-5`
- **来源**：`llm_finding`

**描述**

035.php 第 3 行读取 $_GET['redirect']，仅判断其存在且非空，第 4 行直接拼接到 header("location: " . $_GET['redirect']) 中并 exit。代码未做任何白名单、协议校验、域名校验或相对路径限制，攻击者可传入任意外部 URL（如 https://evil.example/），使服务端返回 302 跳转到攻击者站点。该端点无需认证即可访问，常被用于钓鱼、OAuth/SSO 回调劫持、绕过 Referer 校验等场景。

**source / sink**

- source：query `redirect`（035.php:3）
- sink：035.php:5 header("location: " . $_GET['redirect']) 响应头注入/重定向

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `035.php:3` | 从 $_GET 读取 redirect 参数，仅校验存在且非空 | 攻击者完全可控的字符串 | 仅 array_key_exists 与非空判断，无任何内容校验 |
| 2 | `035.php:4` | 将参数直接拼接到 Location 响应头并发送 | 未过滤的外部 URL 进入响应头 | 无白名单/协议/域名校验，可指定任意绝对 URL |
| 3 | `035.php:5` | exit 终止脚本，仅返回重定向响应 | 重定向生效 |  |

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

攻击者可构造可信域名的链接诱导用户跳转到钓鱼站点，或用于 OAuth/SSO 回调劫持、绕过基于 Referer/域名的访问控制。

**CVE / CWE 论证**

CWE-601 URL 重定向到不可信站点。外部可达、无需认证、链闭合（source→sink 直接相连），属可被 SRC/赏金平台接收的开放重定向。

**修复建议**

对 redirect 目标做白名单校验：仅允许相对路径或以受信域名开头的绝对 URL；拒绝包含 scheme/host 的外部地址，或改用映射表将标识符映射到固定目标。

**验证说明**

需确认 035.php 的实际可达 URL 与部署方式；header() 前无输出（第 1-2 行为 <?php 与空行），重定向可正常发送。若前置 WAF 拦截外部 URL 需另行评估。
模型 POC 要点：构造 redirect 参数指向外部恶意站点，观察 302 跳转
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /035.php）：针对 035.php 第 5 行的开放重定向（CWE-601）。GET 参数 redirect 的值被直接用于跳转目标，未做白名单/同源校验；payload 为 //example.com，浏览器会将其解析为协议相对 URL 并跳转到外部主机。目标地址统一使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /035.php）：符合 CWE-601（URL 重定向到不可信站点）。漏洞位于 035.php:5，外部输入来自 GET 参数 redirect，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅文本工件，不执行、不联网。手工复现时把 TARGET 替换为授权测试实例；用 -i 或 -D - 查看响应头，重点检查 Location。不要对生产环境或未授权目标发送请求。

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
| safety_guard | 安全防护 | 3.36 | 是 |
| surface_mapper | 攻击面测绘 | 7.83 | 是 |
| deep_finder | LLM 深挖 | 7.27 | 是 |
| candidate_screener | 候选筛选 | 3.15 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.86 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.5 | 是 |
| coordinator | 管线协调 | 5.47 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
