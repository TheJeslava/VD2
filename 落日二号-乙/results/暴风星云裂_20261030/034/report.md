# 落日二号乙漏洞挖掘报告 — 20261030-224920-be794b

- 生成时间：2026-10-30T14:49:46.182375+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\034.zip`
- 输入模式：`zip`
- SHA256：`017f433a8e9090aa42467f885f1acd0bb69513cfebb57a3bf352d9244a244cd9`
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

本次汇总的 findings 为空（type_counts 为空，with_poc=0），没有任何已确认漏洞或 POC 交付。覆盖范围仅 1 个 PHP 文件（034.php，21 行、约 398 字节），无框架、无路由、无 HTTP 端点清单，攻击面测绘仅标注 034.php 第 4 行一个 source 热点，sink 热点列表为空，因此无法确认污点是否到达危险汇点。最高危的待确认方向是 034.php:4 外部输入向下游文件操作/包含/命令执行/SQL 拼接/输出回显的数据流（path_traversal、LFI、XSS 均属待确认，非结论）。POC 不齐全：既无 HTTP POC，也无静态证据 POC。需强调：findings 为空不等于不存在漏洞，而是本次输入未提供源码正文与 sink 信息，无法完成数据流分析。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 527 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单个 PHP 文件 034.php（21 行），已完整审计第 1-21 行。该脚本为独立页面，入口即 /034.php。发现一条闭合链：$_GET['redirect']（034.php:3）经 strpos 子串包含校验（034.php:4）后直接拼入 header('location: ...')（034.php:5），构成开放重定向（CWE-601），严重级别按 policy 的 min_severity=high 属中危，低于当前档位阈值，但利用链完整、证据充分，故作为候选交付供人工按档位取舍。未发现命令执行、SQL 注入、文件包含、反序列化等 sink；文件中无 md5/sha1、无 mcrypt/openssl、无 rand/mt_rand、无 setcookie，故 weak_hash/weak_crypto/weak_random/insecure_cookie 均无证据，不报告。未发现 prompt_injection 诱导文本。未覆盖范围：无部署配置（php.ini、allow_url_include、open_basedir）、无 Web 服务器/反向代理配置、无认证机制说明，无法评估是否存在前置认证或 WAF 对 Location 头的改写；code_pack 之外文件视为不存在。

未覆盖 / 证据缺口：
- 无部署配置，无法确认 header 跳转是否被反向代理/WAF 拦截或改写
- 无认证与路由信息，无法确认该页面是否对外直接暴露
- 未提供 PHP 版本，无法评估 header() 对特殊字符的处理差异

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
| safety_guard | 安全防护 | 3.1 | 是 |
| surface_mapper | 攻击面测绘 | 8.25 | 是 |
| deep_finder | LLM 深挖 | 8.64 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.16 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
