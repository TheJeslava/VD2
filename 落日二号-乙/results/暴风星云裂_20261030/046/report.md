# 落日二号乙漏洞挖掘报告 — 20261030-225103-bd69c8

- 生成时间：2026-10-30T14:51:26.284389+00:00
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

本次汇总的 findings 为空（type_counts 为空，with_poc=0），没有任何已定性的漏洞条目，也没有二次注入链。覆盖统计显示仅 1 个 PHP 文件（046.php，14 行、395 字节），无框架、无路由、无 HTTP 端点清单；source_hot_files 指向 046.php:2 作为外部输入读取点，但 sink_hot_files 为空，属于“有源无汇”缺口，且输入未提供代码正文，因此无法给出语句级结论。最高危的待查方向是 046.php 第 2 行请求参数入口的下游数据流（命令执行/文件包含/SQL 拼接/输出回显），其次是同文件的配置实现类风险（weak_hash / weak_random / hardcoded_secret / insecure_cookie / weak_crypto）。POC 不齐全：本次 0 条 POC，既无 HTTP POC 也无静态证据 POC。需强调：findings 为空是“未交付”，不等于“不存在漏洞”。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 489 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单文件 046.php（14 行，DVWA weak_id 模块片段）。逐行审计结果：第 5 行仅判断 REQUEST_METHOD 是否为 POST；第 6-9 行使用服务端 $_SESSION['last_session_id_high'] 自增计数，该值完全由服务端维护，攻击者无法直接控制；第 10 行 md5() 作用于该自增整数，属于可预测会话标识（CWE-330/CWE-340 弱随机/可预测 ID），而非对攻击者可控输入做哈希，不构成 weak_hash（CWE-328）意义上的口令/令牌哈希缺陷；第 11 行 setcookie 显式传入 secure=false、httponly=false，且 domain 取自 $_SERVER['HTTP_HOST']（Host 头），存在 insecure_cookie 与 Host 头注入 cookie domain 的迹象。但按本次 policy（min_severity=high、min_confidence=0.6），上述两项均属中低危配置类问题：可预测会话 ID 需要与认证/会话绑定逻辑配合才能形成会话劫持链，而该文件内未见 session_start、未见将 dvwaSession 用于身份校验的代码，链路不闭合；insecure_cookie 单独不构成高危。因此不产出 finding，仅作为线索记录。未发现命令注入、SQL 注入、文件包含、反序列化等可闭合的高危链。

未覆盖 / 证据缺口：
- 046.php 中未见 session_start()，$_SESSION 的初始化位置不在 code_pack 内，无法确认会话是否真正建立
- dvwaSession cookie 的消费点（校验逻辑）不在 code_pack 内，可预测 ID 是否可导致会话劫持无法闭合
- setcookie 的 domain 参数取自 $_SERVER['HTTP_HOST']，Host 头可控性依赖 Web 服务器配置，未提供 nginx/apache 配置
- 无端点清单与部署配置，无法确认脚本对外暴露路径
- medium_review_items 中的 weak_random（可预测自增 ID + md5）与 insecure_cookie（secure/httponly 均为 false）证据存在但低于本次 min_severity=high 阈值，按策略不交付，不代表不存在

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
| safety_guard | 安全防护 | 3.69 | 是 |
| surface_mapper | 攻击面测绘 | 8.2 | 是 |
| deep_finder | LLM 深挖 | 5.14 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.33 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
