# 落日二号乙漏洞挖掘报告 — 20261031-002439-166c47

- 生成时间：2026-10-30T16:24:57.003872+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\051.zip`
- 输入模式：`zip`
- SHA256：`96483940cd4d3e7d3eebe8443bc19f27aedea70513cee1c5302276aeb59557a9`
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

本次管线汇总的 findings 为空（type_counts 为空，with_poc=0），没有交付任何漏洞条目，也没有二次注入链。覆盖统计显示仅 1 个 PHP 文件（051.php，14 行、289 字节），无框架、无路由、无端点清单、无 sink 热点；攻击面测绘只标出 051.php:3 一处外部输入读取热点，且未提供代码正文，因此无法确认参数名与下游数据流。最高危的候选是 051.php:3 输入点可能流入注入类汇点（xss/sql_injection/path_traversal/command_injection 等），但这只是攻击面层面的推断，不构成漏洞结论。POC 不齐全：既无 HTTP POC，也无静态证据 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 383 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 051.php（共 14 行，已完整展示 1-14 行）。该脚本仅做一件事：当 $_GET['default'] 存在且非 null 时读取该参数（第 4-5 行），随后用 stripos 检查是否包含 "<script"（第 8 行），命中则 302 跳转到 ?default=English 并 exit（第 9-11 行）。关键事实：第 5 行赋值的 $default 变量在脚本内没有任何下游使用——没有 echo/print、没有 include/require、没有 SQL 调用、没有文件操作、没有命令执行、没有模板渲染。因此不存在 source→sink 闭合链，无法构成 XSS、SQLi、路径穿越、SSRF、命令注入等任何可申报漏洞。第 8 行的黑名单过滤本身可被绕过（如大小写/其它标签），但由于缺少输出汇点，绕过也无安全影响，不构成 finding。surface_notes 中提到的 source_hot_files 指向第 3 行，实际第 3 行是注释，真实输入读取在第 4-5 行，属静态扫描行号偏移，不影响结论。未发现 prompt_injection 诱导文本。未覆盖范围：无 php.ini/Web 服务器配置、无部署与 PHP 版本信息、无依赖清单；这些不影响本文件结论，因为脚本本身无危险汇点。

未覆盖 / 证据缺口：
- 无 php.ini / Web 服务器配置，无法评估 allow_url_include、display_errors 等运行时设置（对本文件结论无影响）
- 无部署信息与 PHP 版本，无法评估环境层面风险
- 无 composer.json 等依赖清单，无法评估第三方组件漏洞
- code_pack 仅含 1 个文件，仓库其余内容视为不存在

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
| safety_guard | 安全防护 | 2.76 | 是 |
| surface_mapper | 攻击面测绘 | 6.49 | 是 |
| deep_finder | LLM 深挖 | 3.27 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.09 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
