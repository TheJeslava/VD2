# 落日二号乙漏洞挖掘报告 — 20261031-001726-f37a36

- 生成时间：2026-10-30T16:17:45.889691+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\004.zip`
- 输入模式：`zip`
- SHA256：`b9fab202b9a48529e59fc3b093ab407f0b2c3c52e487f6da9dfafce8e36fbfc5`
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

本次汇总的 findings 为空：管线未交付任何已确认漏洞，with_poc=0，因此没有任何 HTTP POC 或静态证据 POC 可供复现。覆盖统计显示仓库仅含 1 个 PHP 文件（004.php，17 行、292 字节），无框架、无路由、无端点清单，languages 仅 php，quarantined 为空。surface_notes 明确指出 source_hot_files 与 sink_hot_files 同时为空属于测绘盲区而非安全证据，且本次输入未包含 004.php 的任何源码内容，因此无法进行行级审计或污点分析，不能对命令执行、文件包含、反序列化、注入类汇点或配置类风险下任何结论。最高危项无法判定——不是因为确认安全，而是因为缺少代码证据。POC 不齐全（0/0），无动态验证，也无静态证据 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 401 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 004.php（17 行），内容为：第 12 行调用 dvwaCurrentUser() 与字符串 "admin" 比较，不相等则第 13-15 行打印 Unauthorised、返回 403 并 exit。该文件本身不含任何外部输入读取（无 $_GET/$_POST/$_COOKIE/$_SERVER）、不含命令执行/文件包含/SQL/反序列化/模板等危险汇点，也不含哈希、加密、随机数、Cookie 标志位等配置型证据，因此无法在 004.php 内闭合任何 source→sink 利用链。注释第 8 行指向 vulnerabilities/authbypass/change_user_details.php，但该文件不在 code_pack 中，按零工具契约视为不存在，不能据此推断漏洞；dvwaCurrentUser() 的实现同样未提供，无法判断其是否可被客户端输入（如 Cookie）伪造，属于未闭合线索。surface_notes 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 复核项在可见代码中均无对应实现，不构成候选。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 的定义未在 code_pack 中，无法判断认证判断是否可被 Cookie/Header 伪造（潜在 auth_bypass 线索，证据不足）
- 注释引用的 vulnerabilities/authbypass/change_user_details.php 未提供，无法审计
- 无部署配置与 php.ini 信息，无法判断可达性
- 无 HTTP 端点清单，实际暴露面未知

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
| safety_guard | 安全防护 | 2.77 | 是 |
| surface_mapper | 攻击面测绘 | 7.48 | 是 |
| deep_finder | LLM 深挖 | 3.46 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.23 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
