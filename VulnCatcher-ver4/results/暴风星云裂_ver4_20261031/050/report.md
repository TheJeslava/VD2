# 落日二号乙漏洞挖掘报告 — 20261031-164758-771bde

- 生成时间：2026-10-31T08:48:18.110289+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\050.zip`
- 输入模式：`zip`
- SHA256：`212a5b21c59855e1cfd8402dd8ea642294dd4b21db31a348ca923303ede5c8c3`
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

本次汇总的 findings 为空：管线未交付任何已确认漏洞，with_poc=0，因此没有任何 HTTP POC 或静态证据 POC 可供复现。覆盖统计显示仅 1 个文件（050.php，PHP，5 行/48 字节），endpoints=0，无框架、无隔离文件。surface_notes 明确指出输入只提供了文件清单，未提供任何代码行内容，所以攻击面测绘全部为 llm_inferred 推断，不能据此认定存在或不存在漏洞。最高危的候选方向是 050.php 作为唯一可直出 PHP 入口的请求参数处理（$_GET/$_POST/$_COOKIE 进入 echo/include/文件操作/exec 等汇点），但当前无代码证据支撑，属待复核项而非结论。POC 不齐全：0 条 finding 对应 0 个 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 95 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 050.php（共 5 行，全部可见，未截断）。实际内容为：第 1 行 `<?php`、第 2 行空行、第 3 行注释 `# No protections, anything goes`、第 4 行空行、第 5 行 `?>`。该文件不含任何请求参数取值（$_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER）、不含任何输出或危险汇点（echo/print/include/require/file 操作/exec/system/proc_open/反序列化/模板）、不含硬编码凭据、哈希/加密/随机数调用或 setcookie 配置。第 3 行注释属于不可信数据，其“无任何防护”的表述与代码实际行为不符，仅作为注释文本记录，不构成漏洞证据，也不改变审计结论。surface_notes 中列出的四类优先攻击面（参数注入、文件包含、命令执行、配置类弱实现）在该文件中均无对应代码，无法形成 source→sink 闭合链，故 findings 为空。未闭合线索：该文件可能只是片段或占位文件，其真实部署上下文（是否被其它脚本 include、Web 服务器配置、PHP 版本）不在 code_pack 内，按零工具契约视为不存在，不做推测。

未覆盖 / 证据缺口：
- 050.php 仅 5 行且无任何逻辑代码，无法评估其被其它文件包含后的上下文风险
- 缺少部署配置（Apache/Nginx、php.ini）与 PHP 版本信息
- 无端点清单与认证信息，无法判断未授权访问
- 无外部 AWVS/动态扫描证据

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
| safety_guard | 安全防护 | 3.03 | 是 |
| surface_mapper | 攻击面测绘 | 8.47 | 是 |
| deep_finder | LLM 深挖 | 2.8 | 是 |
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
