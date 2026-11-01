# 落日二号乙漏洞挖掘报告 — 20261031-010213-6d1b71

- 生成时间：2026-10-30T17:02:31.774131+00:00
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

本次汇总的 findings 为空（type_counts 为空，with_poc=0），没有任何已确认漏洞或 POC 交付。覆盖统计显示仅 1 个 PHP 文件（030.php，10 行、222 字节），无框架、无路由、无端点清单，sink_hot_files 为空，source_hot_files 仅标记 030.php 第 1 行。因此最高危项无法确定：既没有已确认的高危漏洞，也不能据此断言该脚本安全——攻击面测绘明确指出「sink_hot_files 为空不等于无汇点」，只是静态扫描未命中已知模式。POC 不齐全（0 条），且本次输入未提供 030.php 的实际代码内容，无法产出可复现 POC 文本。未发现 prompt_injection 证据。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 296 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 030.php（共 10 行，已完整展示 1-10 行）。该脚本读取 $_GET['page']（第 4 行），随后仅做两次 str_replace 过滤：第 7 行删除 http:// 与 https://，第 8 行删除 ../ 与 ..\。脚本在第 10 行以 ?> 结束，CODE PACK 中不存在任何 include/require、file_get_contents、fopen、readfile、echo/print、SQL 调用或其它 sink；因此 source（$_GET['page']）到危险汇点的链路在给定代码内不闭合，无法构造可复现 POC。按零容忍误报原则不申报 finding。需要说明的线索：(1) 第 7/8 行的黑名单式过滤本身是典型的可绕过写法（如 ....//、..%2f、绝对路径 /etc/passwd、php://filter 等），若后续版本或未展示的代码把 $file 传入 include/readfile 即构成 LFI/路径遍历，但当前 code_pack 无此汇点，属未闭合线索；(2) 未发现 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 相关调用（无 md5/sha1/rand/setcookie/$_SERVER 使用）；(3) 输入中未出现诱导性文本，无 prompt_injection 证据。未覆盖范围：无 composer.json、Web 服务器配置、php.ini、路由与端点清单，无法确认该脚本的对外 URL、认证要求及运行时条件；这些均超出 code_pack，按契约视为不存在。

未覆盖 / 证据缺口：
- 030.php 中 $file 变量在过滤后未被任何 sink 使用，source→sink 链不闭合
- 无部署配置/php.ini/路由信息，无法确认对外暴露方式与认证要求
- 无依赖清单，无法评估第三方库 CVE
- 第 7/8 行黑名单过滤可绕过性仅为潜在线索，缺少实际汇点无法申报

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
| safety_guard | 安全防护 | 2.65 | 是 |
| surface_mapper | 攻击面测绘 | 7.12 | 是 |
| deep_finder | LLM 深挖 | 3.71 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 4.86 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
