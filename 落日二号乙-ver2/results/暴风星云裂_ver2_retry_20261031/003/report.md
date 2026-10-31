# 落日二号乙漏洞挖掘报告 — 20261031-001726-445edc

- 生成时间：2026-10-30T16:17:49.160452+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\003.zip`
- 输入模式：`zip`
- SHA256：`06085614e8d510ff9f2f368ced0a790b64e5926adc00f379d25132aa3a2a79d0`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`high`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总的 findings 为空：去重后没有任何已确认漏洞，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。攻击面测绘只覆盖 1 个 PHP 文件（003.php，98 行，约 2.6KB），无框架、无路由、无端点清单、无认证文件、无依赖清单，入口只能从源码推断为直接访问该 .php 文件。source 热点与 sink 热点均集中在 003.php（各 2 处），提示同一文件内可能存在外部输入与危险汇点的闭环，但当前没有任何一条数据流被确认为漏洞，最高危项无法确定。结论：本次无可交付漏洞，POC 不齐全（0/0），所有风险点均为源码层面的待复核项，未经任何动态验证。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3115 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 003.php（1-98 行，未截断）。该脚本从 $_SERVER['REQUEST_URI'] 取值（第 3 行），用 str_replace 去掉固定前缀 "/vulnerabilities/api/"（第 4 行），再把结果 $stripped_url 直接拼进两处内联 <script> 的 JS 字符串常量（第 31、51 行），构成服务端反射到客户端脚本上下文的注入点。但按当前策略 min_severity=high、min_confidence=0.6，该问题只能归为反射型 XSS（需受害者点击构造 URL，且注入点位于 JS 单引号字符串内，需闭合引号，利用价值有限），严重度达不到 high 档，故不作为 finding 交付，仅在此记录线索：source=$_SERVER['REQUEST_URI']（003.php:3）→ str_replace 仅做前缀删除、无 HTML/JS 编码（003.php:4）→ 拼接进 <script> 内 const url = '...'（003.php:31、003.php:51）→ 浏览器执行。第 83 行 $_SERVER['PHP_SELF'] 拼进 form action 属性，同样未编码，属同类反射型 XSS 线索。文件中未出现 SQL/XPath/LDAP 查询、文件读写、include/require、system/exec/shell_exec/popen、反序列化、模板渲染、SSRF 或 setcookie/session 配置，故 command_injection、sql_injection、path_traversal、deserialization、ssrf、weak_hash、weak_crypto、weak_random、insecure_cookie 均无证据。第 80 行注释与页面文案（"exploit it to elevate your user to admin"）属于不可信数据中的业务提示，指向的 /vulnerabilities/api/v2/user/2 接口实现不在 code_pack 内，视为不存在，无法闭合越权/业务逻辑链。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- 反射型 XSS 线索（003.php:3-4→31/51/83）因严重度低于 min_severity=high 未交付，需人工评估是否降档接收
- 页面引用的 /vulnerabilities/api/v2/user/2 GET/PUT 接口实现不在 code_pack，无法判断是否存在越权修改 level 的业务逻辑漏洞
- 无 php.ini、Web 服务器配置、composer.json、README，运行环境与安全基线未知
- 无端点清单，实际路由与请求方法只能从源码推断

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
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.31 | 是 |
| surface_mapper | 攻击面测绘 | 8.85 | 是 |
| deep_finder | LLM 深挖 | 3.67 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 6.99 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
