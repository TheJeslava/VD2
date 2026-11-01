# 落日二号乙漏洞挖掘报告 — 20261031-010535-c12225

- 生成时间：2026-10-30T17:05:59.150023+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\051.zip`
- 输入模式：`zip`
- SHA256：`96483940cd4d3e7d3eebe8443bc19f27aedea70513cee1c5302276aeb59557a9`
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

本次汇总的 findings 为空：类型统计为空、with_poc=0，没有任何已确认漏洞或 POC 交付。覆盖统计显示仅 1 个 PHP 文件（051.php，14 行），0 个 HTTP 端点、无框架、无隔离项。攻击面测绘指出 051.php:3 存在一个外部输入读取热点，但输入未提供该行及后续代码文本，sink_hot_files 为空，因此无法把任何注入类结论落到具体变量与汇点。最高危的待查方向是 051.php:3 输入是否连通 include/require、动态函数调用（$func()、call_user_func、eval）或文件路径拼接，一旦连通等价于任意代码执行/文件包含；其次是配置实现类风险（weak_hash、weak_random、insecure_cookie、hardcoded_secret）。POC 不齐全：本次无任何 POC，且因缺少代码文本，连静态证据 POC 也无法产出。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 383 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单文件 051.php（14 行，已完整展示 1-14 行）。逐行审计结果：第 4 行通过 array_key_exists("default", $_GET) 读取外部参数 default，第 5 行赋值给 $default，第 8 行用 stripos($default, "<script") 做黑名单校验，命中则第 9 行 header("location: ?default=English") 跳转并 exit。关键事实：$default 在第 5 行赋值后，除第 8 行的 stripos 检查外，在可见的 14 行内没有任何输出、拼接、include/require、动态函数调用、SQL、文件操作或命令执行汇点——脚本在第 12 行结束 if 块后直接闭合 PHP 标签，$default 从未被回显或使用。因此不存在可闭合的 source→sink 链：既无反射型 XSS（无 echo/print 输出该变量），也无文件包含、命令注入、SQL 注入、路径穿越。surface_notes 中关于“第 3 行为 source 热点”的描述与实际代码不符（第 3 行是注释，真实输入读取在第 4-5 行），且 sink_hot_files 为空与代码实际一致——本脚本确实没有危险汇点。medium_review_items 中列出的 weak_hash / weak_random / insecure_cookie / hardcoded_secret / trust_boundary 均为基于“单文件脚本常见写法”的推测，代码中不存在 md5/sha1/rand/mt_rand/setcookie/mysqli_connect/include 等任何对应调用，不予立项。未发现 prompt_injection 证据。按“宁可漏报不可误报”原则，findings 为空。

未覆盖 / 证据缺口：
- code_pack 仅含 051.php 一个文件，若该脚本被其他文件 include 或作为模板片段被上层路由调用，其真实入口与参数传递链不在可见范围内
- 缺少 Web 服务器与 php.ini 配置（allow_url_include、open_basedir、disable_functions），无法评估部署暴露面
- 无依赖清单与数据库配置，无法评估第三方组件 CVE 或 SQL 权限上下文
- surface_notes 声称第 3 行为 source 热点，但实际代码第 3 行为注释、输入读取在第 4-5 行，说明上游静态测绘与实际代码存在偏差，其余热点判断的可信度需谨慎对待

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
| safety_guard | 安全防护 | 2.63 | 是 |
| surface_mapper | 攻击面测绘 | 9.18 | 是 |
| deep_finder | LLM 深挖 | 3.59 | 是 |
| candidate_screener | 候选筛选 | 2.48 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 6.08 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
