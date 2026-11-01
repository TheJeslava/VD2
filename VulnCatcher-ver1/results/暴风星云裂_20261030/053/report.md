# 落日二号乙漏洞挖掘报告 — 20261030-225153-c99548

- 生成时间：2026-10-30T14:52:16.166956+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\053.zip`
- 输入模式：`zip`
- SHA256：`dec73bedc036c1309393989aea493094094031b09deb800e5d4d4666bfc8824e`
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

本次汇总的 findings 为空：类型统计为空，带 POC 的条目为 0，二次注入链为空。覆盖范围仅 1 个 PHP 文件（053.php，11 行 / 229 字节），无框架、无路由、无端点清单。攻击面测绘仅能确认 053.php 第 3 行存在请求参数读取点（source_hot_files），但 sink_hot_files 为空，未识别到命令执行、SQL、文件、反序列化等危险汇点，因此本次没有任何可交付的漏洞结论，也没有最高危项可排序。POC 方面：HTTP POC 与静态 POC 均为 0，不存在“POC 齐全”的情况，也不存在可动态复现的结论。需要强调：sink 为空更可能是规则未覆盖该脚本所用函数（eval/assert/preg_replace /e/create_function/动态 include/file_get_contents 远程 URL/unserialize）造成的检测盲区，而不是“无风险”；且本次未提供 053.php 的语句级正文，无法做数据流判定。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 308 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 053.php（11 行）。已通读全文：第 3 行发送 X-XSS-Protection: 0；第 6 行读取 $_GET['name']；第 8 行未编码拼接进 HTML 输出，构成反射型 XSS（CWE-79），链闭合。未发现命令执行、SQL、文件读写、反序列化、include/eval 等其它 sink。surface_notes 中 source_hot_files 指向第 3 行实为 header 调用而非参数读取，真正入口在第 6 行。无配置文件、路由与部署信息，无法确认可达路径与运行环境；无认证/会话/加密线索，故无 weak_crypto/weak_hash/insecure_cookie 类候选。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- 无 HTTP 端点/路由信息，无法确认 053.php 的可达 URL 与请求方法
- 无 Web 服务器/php.ini 配置，无法确认危险函数是否启用及部署暴露状态
- 无会话/认证代码，无法评估 XSS 窃取 Cookie 的实际收益
- 仅 1 个文件，无依赖与版本信息，无法关联已知 CVE

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
| safety_guard | 安全防护 | 3.63 | 是 |
| surface_mapper | 攻击面测绘 | 6.59 | 是 |
| deep_finder | LLM 深挖 | 6.73 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 6.14 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
