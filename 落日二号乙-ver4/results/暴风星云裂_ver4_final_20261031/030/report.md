# 落日二号乙漏洞挖掘报告 — 20261031-173004-6a7a47

- 生成时间：2026-10-31T09:30:24.369359+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\030.zip`
- 输入模式：`zip`
- SHA256：`48d4b3a99200d915a9607662d8cd6ecde38870f14e54fee1fcb0210945f67000`
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

本次汇总的 findings 为空数组，type_counts 为空，with_poc=0，即没有任何已确认漏洞、也没有任何 POC 文本（既无 HTTP POC，也无静态证据 POC）。覆盖统计显示仓库仅 1 个 PHP 文件（030.php，10 行、222 字节），无框架、无路由、无端点清单，source_hot_files 仅标记第 1 行，sink_hot_files 为空，属于典型「有源无汇」识别缺口。因此本次最高危结论只能是：无已交付漏洞，但攻击面未被有效审计，不能据此判定项目安全。POC 齐全性：不适用（无 finding 可配 POC）。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 296 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个文件 030.php（10 行）。已通读全部 10 行：第 4 行从 $_GET['page'] 取外部输入，第 7-8 行做黑名单式过滤（str_replace 去除 http://、https://、../、..\），但文件中不存在任何输出语句（echo/print）、文件包含（include/require）、文件读写（fopen/file_get_contents）或命令执行（system/exec/shell_exec/passthru）等汇点，脚本在第 10 行直接结束。因此 source 存在但 sink 缺失，无法构成闭合的 source→sink 利用链，按零容忍误报原则不产出 finding。<br><br>未闭合线索（证据不足，不单独立项）：<br>1) 第 7-8 行的黑名单过滤本身是典型的“假防护”写法——str_replace 只做一次替换，可用 '....//' 或 'hthttp://tp://' 等嵌套构造绕过，且未做 realpath 规范化。若后续版本或未送入的代码中存在 include($file) / file_get_contents($file) / readfile($file)，则立即构成 path_traversal 或 SSRF（http:// 前缀被剥离后仍可拼接）。当前 code_pack 中无此汇点，故不报告。<br>2) 变量 $file 在第 8 行后未被使用，属于死代码或代码被截断的迹象；需人工确认是否存在被裁剪的后续行（total_lines=10 与 shown_ranges 1-10 一致，未见截断标记，但无法排除仓库外文件）。<br>3) 配置类攻击面（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）在本文件中均无对应函数调用（无 md5/sha1、无 rand/mt_rand、无 setcookie、无 $_SERVER 头信任），已排除。<br>4) 无端点清单、无框架、无依赖清单，无法评估部署层（php.ini、register_globals、错误显示）带来的额外攻击面。<br><br>结论：在给定 code_pack 范围内未发现可申报 CVE 的漏洞。

未覆盖 / 证据缺口：
- 030.php 中 $_GET['page'] 无对应 sink，链路不闭合
- 黑名单过滤可绕过但缺少下游危险操作，无法升级为可利用漏洞
- 无配置文件、端点清单、依赖清单，部署层攻击面未覆盖
- 仓库外文件按契约视为不存在，未审计

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
| safety_guard | 安全防护 | 3.47 | 是 |
| surface_mapper | 攻击面测绘 | 6.29 | 是 |
| deep_finder | LLM 深挖 | 4.41 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.74 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
