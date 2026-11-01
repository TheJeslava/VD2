# 落日二号乙漏洞挖掘报告 — 20261031-002415-d5e532

- 生成时间：2026-10-30T16:24:37.441825+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\048.zip`
- 输入模式：`zip`
- SHA256：`7be45c1a53974d969c5fea706096bfd9b3d27604468af7e49423890e14859d57`
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

本次汇总的 findings 为空（type_counts 为空，with_poc=0），没有任何已确认漏洞，也没有二次注入链。覆盖统计显示仅 1 个 PHP 文件（048.php，9 行、145 字节），无框架、无路由、无端点清单；source_hot_files 标记 048.php 行 1 为输入读取热点，但 sink_hot_files 为空，且管线未提供该文件源码内容，因此无法做行级审计，也无法确认任何注入类或配置类问题。最高危的潜在方向是「048.php 的请求参数入口直接流入 SQL/命令/文件路径/输出」这一单文件完整利用链假设，但当前仅为范围级推断（llm_inferred），无行号、无变量名、无汇点证据，不能作为结论。POC 完全缺失（with_poc=0），既无 HTTP POC 也无静态证据 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 212 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 048.php（共 9 行，完整可见）。该脚本仅在 POST 请求时执行 `$cookie_value = time(); setcookie("dvwaSession", $cookie_value);`，无任何外部输入读取（未使用 $_GET/$_POST/$_COOKIE/$_SERVER 中的用户可控值参与逻辑），无 SQL/命令/文件/模板/反序列化等危险汇点，也无输出反射点。会话标识使用 time() 生成属于弱随机/可预测会话 ID（CWE-330/CWE-340），但：1) 该值仅作为 Cookie 值下发，脚本内无任何基于该 Cookie 的鉴权或状态校验逻辑，无法在本次可见代码内构成会话劫持闭环；2) setcookie 未设置 secure/httponly/samesite 属不安全 Cookie 标志（CWE-614/CWE-1004），但同样缺少消费该 Cookie 的服务端逻辑证据。二者均低于 min_severity=high 且利用链不闭合，按“宁可漏报不可误报”原则不单独立项，仅作为线索记录。未覆盖范围：无 HTTP 端点清单、无框架/部署配置、无依赖清单，无法确认该脚本在真实应用中的调用上下文与 Cookie 消费方；若后续提供消费 dvwaSession 的鉴权代码，可重新评估会话预测/固定风险。

未覆盖 / 证据缺口：
- 048.php 中 time() 生成的 dvwaSession 无服务端消费逻辑，弱随机会话 ID 无法闭合为会话劫持
- setcookie 缺少 secure/httponly/samesite 标志，但无鉴权上下文可评估影响
- 无端点清单、部署配置与依赖信息，无法评估真实暴露面

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
| safety_guard | 安全防护 | 3.07 | 是 |
| surface_mapper | 攻击面测绘 | 8.3 | 是 |
| deep_finder | LLM 深挖 | 3.53 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 6.65 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
