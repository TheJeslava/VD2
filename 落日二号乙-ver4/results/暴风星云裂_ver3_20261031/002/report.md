# 落日二号乙漏洞挖掘报告 — 20261031-005721-b00246

- 生成时间：2026-10-30T16:57:45.261379+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\002.zip`
- 输入模式：`zip`
- SHA256：`e1763d6f3dacb5f1144d8bf313ac2128337f0729a834123f8f766fea9b793fc2`
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

本次汇总的 findings 为空数组，type_counts 为空，with_poc=0，即没有任何已去重的漏洞条目交付，也没有任何 POC（既无 HTTP POC，也无静态证据 POC）。覆盖统计显示仅 1 个 PHP 文件（002.php，121 行，约 3.1KB），端点数为 0，无框架、无路由配置，属于独立 PHP 页面型代码。攻击面测绘指出 source 热点在 002.php:2、sink 热点在 002.php:4，两者行距极近，提示参数读取后几乎未经净化即进入危险汇点，是本次最高价值的审计目标；但由于发现阶段未产出任何 finding，该短路径注入（command_injection / sql_injection / path_traversal / 文件包含 / 反射型 XSS）均处于未交付状态，不能据此宣称不存在。最高危的潜在面是 002.php:2→002.php:4 的短路径注入，其次是文件包含/路径拼接与输出反射 XSS。POC 不齐全：0 条 finding 对应 0 个 POC，且因端点清单为空，任何后续 POC 只能以 TARGET 占位。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3749 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 002.php（1-121 行，未截断）。该文件是一个纯前端展示型 PHP 页面：第 6-7 行的 POST 分支为空，没有任何请求参数读取（无 $_GET/$_POST/$_COOKIE/$_REQUEST），因此 surface_notes 中「source 在 002.php:2、sink 在 002.php:4」的热点推断与实际代码不符——第 2-4 行只是三个空字符串变量初始化（$errors/$success/$messages），并非参数读取或危险函数调用。文件中唯一的服务端数据流是第 9 行 $_SERVER['REQUEST_URI'] → 第 10 行 str_replace 去掉固定前缀 "/vulnerabilities/api/" → 第 47 行拼接进 JS 字符串常量 const url = '...'。该值虽来自请求 URI，但被写入 <script> 内的单引号字符串，且 REQUEST_URI 在到达脚本前已被 Web 服务器/浏览器规范化，未发现可闭合的 XSS 或注入链（要闭合需证明可注入单引号并逃逸 script 上下文，而 URI 中的引号通常被编码，证据不足，按「宁可漏报」原则不报告）。第 20-44、46-97 行的 JS 逻辑（update_username 使用 innerHTML 拼接 user_json.name、loadTableData 使用 cell.innerHTML = value）属于客户端 DOM 渲染，数据源是同源 API /vulnerabilities/api/v2/user/ 的响应，不在本 code_pack 内，无法确认服务端是否对 name 字段做转义，故不构成可闭合的服务端漏洞。未发现命令执行、SQL、文件包含、反序列化、SSRF、硬编码凭据、弱哈希/弱随机/弱加密、setcookie 等任何 sink；medium_review_items 中列出的 weak_hash/weak_random/weak_crypto/insecure_cookie/trust_boundary 在代码中均无对应实现。输入中未出现诱导性文本，无 prompt_injection 证据。未闭合线索：第 47 行 $stripped_url 的反射若在特定服务器对 REQUEST_URI 不做编码时可能形成反射型 XSS，但缺少部署层证据；第 34/94 行 innerHTML 的存储型 XSS 取决于 code_pack 之外的 API 实现。

未覆盖 / 证据缺口：
- code_pack 仅含 002.php，无 composer.json、Web 服务器配置、.htaccess，无法确认部署与 URI 规范化行为
- 端点清单为空，无法确认 /vulnerabilities/api/v2/user/ 的实际实现与 name 字段转义情况
- 第 47 行 $stripped_url 反射进 <script> 字符串的 XSS 需部署层证据（REQUEST_URI 是否原样含引号）才能闭合
- 第 34/94 行 innerHTML 渲染 API 响应字段的存储型 XSS 依赖 code_pack 之外的后端代码，无法验证

## 3. Findings

未发现满足阈值的候选。

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
| safety_guard | 安全防护 | 2.42 | 是 |
| surface_mapper | 攻击面测绘 | 7.43 | 是 |
| deep_finder | LLM 深挖 | 4.95 | 是 |
| candidate_screener | 候选筛选 | 2.83 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 6.03 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
