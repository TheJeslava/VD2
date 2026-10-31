# 落日二号乙漏洞挖掘报告 — 20261030-224855-51368a

- 生成时间：2026-10-30T14:49:17.544817+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\030.zip`
- 输入模式：`zip`
- SHA256：`48d4b3a99200d915a9607662d8cd6ecde38870f14e54fee1fcb0210945f67000`
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

本次汇总的 findings 为空（type_counts 为空，with_poc=0），没有任何已确认漏洞，也没有二次注入链。覆盖统计显示仅 1 个 PHP 文件（030.php，约 10 行、222 字节），无框架、无端点清单（endpoints=0），quarantined 为空。攻击面测绘把 030.php 标为 source_hot_files（1 处输入源热点），但 sink_hot_files 为空，属于典型的“有输入、无汇点”缺口：当前证据只到输入读取侧，尚未定位危险汇点，因此无法判定属于 xss / path_traversal / command_injection / sql_injection 中的哪一类。最高危的候选方向是短脚本中常见的 include/require 拼接（本地文件包含/路径穿越）与 echo 直接输出（XSS），但均为攻击面定位，不是漏洞结论。POC 方面：无任何 HTTP POC，也无静态证据 POC，POC 不齐全。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 296 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 030.php（共 10 行，完整可见，未截断）。该脚本从 $_GET['page'] 读取输入（第 4 行），随后做两次 str_replace 过滤：第 7 行移除 http:// 与 https://，第 8 行移除 ../ 与 ..\。但脚本在第 10 行结束，没有任何 include/require、echo/print、fopen/file_get_contents、system/exec 等汇点，也没有 setcookie/session_set_cookie_params、md5/sha1、rand/mt_rand、硬编码密钥等配置型证据。因此 source 存在而 sink 缺失，数据流不闭合，无法构造任何可复现利用链。按“宁可漏报不可误报”原则不产出 finding。需要说明：第 7、8 行的黑名单过滤本身是典型的可绕过写法（如 ....//、hthttp://tp://、绝对路径 /etc/passwd、php://filter 等），若后续版本或未送入 code_pack 的代码中存在 include($file) 或 file_get_contents($file)，则极可能构成 path_traversal / LFI；但当前证据不足以确认汇点，故仅作为线索记录，不单独立项。

未覆盖 / 证据缺口：
- 030.php 中无任何危险汇点（include/require、文件读写、命令执行、输出、SQL、反序列化均未出现），source→sink 链不闭合
- 无端点清单，无法确认该脚本是否被其他页面 include 或经重写规则改变可达路径
- 无 php.ini / Web 服务器配置，无法确认 allow_url_include、open_basedir 等影响 LFI 利用的条件
- 第 7、8 行黑名单过滤可被 ....//、hthttp://tp://、绝对路径、php://filter 等绕过，但缺少下游汇点，暂不构成可申报漏洞

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
| safety_guard | 安全防护 | 3.99 | 是 |
| surface_mapper | 攻击面测绘 | 8.42 | 是 |
| deep_finder | LLM 深挖 | 3.66 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.83 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
