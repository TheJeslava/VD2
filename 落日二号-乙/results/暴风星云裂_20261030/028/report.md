# 落日二号乙漏洞挖掘报告 — 20261030-224849-d62441

- 生成时间：2026-10-30T14:49:07.673445+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\028.zip`
- 输入模式：`zip`
- SHA256：`48d6ce05cb08135a9f125237dab9970746dff5e4ee8a3d4ccf3864c33a0226bb`
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

本次汇总的 findings 为空：已去重结果中没有任何类型、任何严重度的漏洞条目，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。覆盖统计显示仅 1 个文件（028.php，PHP，13 行/236 字节），端点数为 0，无框架、无隔离项。攻击面测绘把 028.php 第 1 行标为 source 热点，但 sink_hot_files 为空，且管线未提供该文件的代码片段，因此无法确认任何 source→sink 数据流，也无法给出最高危项。结论是：本次没有可交付漏洞，但这属于证据不足导致的未判定，不能写成“该脚本无漏洞”。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 325 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 028.php（13 行，PHP 单文件脚本）。第 4 行 `$file = $_GET['page'];` 为外部输入源，第 7 行使用 `fnmatch("file*", $file) && $file != "include.php"` 做白名单校验，第 9 行仅 echo 错误信息并 exit。关键缺口：该脚本在校验通过后**没有任何下游使用点**——没有 include/require、没有 file_get_contents/fopen、没有 echo/print 输出 $file、没有 system/exec/eval。也就是说 source 存在、校验存在，但 sink 不存在，数据流在第 7 行之后即终止（脚本第 13 行直接闭合 PHP 标签）。因此无法构成任何闭合的 source→sink 利用链，按零容忍误报原则不产出 finding。<br><br>补充说明：该文件是典型的 DVWA 风格「Local File Inclusion」教学片段的前半部分，真实 LFI 需要后续 `include($file);` 之类的汇点，但 code_pack 中不存在该行，按契约不得假设 code_pack 之外的内容。若管线后续补入完整版本（含 include/require 使用 $file），则第 7 行的 fnmatch 白名单可被 `file://`、`file/../../etc/passwd` 或 PHP 包装器绕过，届时应作为 path_traversal / LFI 重新评估。<br><br>未覆盖范围：无部署配置（php.ini、allow_url_include、open_basedir）、无 Web 服务器重写规则、无认证层信息，均无法评估；但这些不影响本次「sink 缺失」的结论。

未覆盖 / 证据缺口：
- 028.php 第 7 行校验之后无任何危险汇点，数据流不闭合，无法申报漏洞
- 缺少 php.ini / allow_url_include / open_basedir 等部署配置，无法评估潜在 LFI 的利用条件
- 无 Web 服务器配置与认证网关信息，攻击面可达性未知
- 若存在未送入 code_pack 的完整版本（含 include($file)），需重新审计

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
| safety_guard | 安全防护 | 3.59 | 是 |
| surface_mapper | 攻击面测绘 | 5.62 | 是 |
| deep_finder | LLM 深挖 | 4.22 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 4.7 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
