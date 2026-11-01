# 落日二号乙漏洞挖掘报告 — 20261031-002414-2af8aa

- 生成时间：2026-10-30T16:24:32.048875+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\046.zip`
- 输入模式：`zip`
- SHA256：`9d98d51f3b7f8ead39aea7b49f01b44680c06b424521a0bf068da8c5c5a86a40`
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

本次审计范围极小：仅 1 个 PHP 文件（046.php，14 行，约 395 字节），无框架、无路由配置、无端点清单。findings 为空数组，type_counts 为空，with_poc=0，即本次没有任何已交付漏洞，也没有任何 POC（既无 HTTP POC，也无静态证据 POC）。攻击面测绘指出唯一热点是 046.php 第 2 行的请求参数读取点，但 sink_hot_files 为空，管线未识别到显式危险汇点，因此该参数在第 3-14 行的流向尚未被确认，属于未闭环的审计缺口而非已排除风险。最高危的候选方向是 046.php:2 参数值流入 include/require、文件读写、SQL 或 system/exec 类汇点，但当前无代码级证据支撑，不能写成结论。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 489 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含 046.php（14 行）。逐行审计：第 5 行判断 POST 方法，第 6-9 行对 $_SESSION['last_session_id_high'] 做自增，第 10 行用 md5() 对该自增整数做哈希生成 cookie 值，第 11 行 setcookie 写入 dvwaSession（path=/vulnerabilities/weak_id/，httponly=false、secure=false）。该文件是 DVWA weak_id 练习的会话 ID 生成逻辑，属于弱会话 ID 生成（可预测的自增序列经 MD5），但：1) 无任何外部可控输入进入 sink（source_hot_files 标注的第 2 行为空行，实际无参数读取点，surface_notes 的推断与源码不符）；2) 无 include/require、文件读写、SQL、命令执行、反序列化、模板等危险汇点；3) 弱 ID 本身属 weak_random/insecure_cookie 类配置型问题，当前 code_pack 中不存在可闭合的认证绕过或会话劫持利用链（无登录校验、无会话消费点、无其它端点），按 min_severity=high 与零误报原则不单独立项。未闭合线索：若存在同项目内依赖 dvwaSession 做身份判定的其它页面（未在 code_pack 中），弱可预测 ID 可能升级为会话伪造，但该文件不在本次输入范围内，无法确认。

未覆盖 / 证据缺口：
- code_pack 仅 1 个文件，无路由/部署配置，无法确认 046.php 的实际 URL 与请求方法
- 无依赖其它页面（会话校验点）的源码，弱会话 ID 无法闭合为会话伪造链
- surface_notes 声称 046.php:2 为污点源，但源码第 2 行为空行，实际不存在请求参数读取点
- 无数据库/外部服务配置，SQL 注入与 SSRF 不可达

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
| safety_guard | 安全防护 | 3.53 | 是 |
| surface_mapper | 攻击面测绘 | 4.96 | 是 |
| deep_finder | LLM 深挖 | 3.72 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.58 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
