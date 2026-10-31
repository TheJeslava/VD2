# 落日二号乙漏洞挖掘报告 — 20261030-224521-424e8c

- 生成时间：2026-10-30T14:45:37.805000+00:00
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

本次管线未产出任何 findings（findings 为空，type_counts 为空，with_poc=0），因此没有可汇总的漏洞结论，也没有 POC 可交付。覆盖范围仅为单文件 PHP 脚本 004.php（17 行、292 字节），且输入只提供了文件元数据，未提供该文件的代码内容，无法进行行级审计与污点分析，故最高危项无法判定。surface_notes 明确指出：所有注入类与配置类判断均缺乏证据，本报告不做漏洞结论。需强调：findings 为空是“未交付”而非“已确认无漏洞”，尤其本次存在策略档位与未覆盖源码的缺口。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 401 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 004.php（17 行），内容为 DVWA 风格的授权检查片段：第 12 行调用 dvwaCurrentUser() 与字符串 "admin" 比较，不相等则输出 Unauthorised、返回 403 并 exit。该文件内不存在任何外部输入取值（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER）、无 include/require、无文件读写、无 system/exec/eval、无 SQL 拼接、无模板渲染、无反序列化，因此在本文件范围内不存在可闭合的 source→sink 利用链。第 2-10 行注释提到 vulnerabilities/authbypass/change_user_details.php，但该文件不在 code_pack 中，按契约视为不存在，不能据此推断漏洞；注释属不可信数据，仅作线索记录。dvwaCurrentUser() 的实现未提供，无法判断其是否可被客户端 Cookie/Header 伪造（若其直接信任客户端可控的会话标识，则可能构成认证绕过），这是唯一未闭合的高价值线索，需在拿到该函数实现后重新评估。此外无部署配置、无依赖清单、无端点表，无法评估配置类问题（weak_crypto/weak_hash/insecure_cookie/hardcoded_secret 等）。按 min_severity=high、min_confidence=0.6 的策略，本次不交付任何 finding。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 的实现未在 code_pack 中，无法判断认证判定是否可被客户端伪造（潜在 auth_bypass 线索未闭合）
- 注释引用的 vulnerabilities/authbypass/change_user_details.php 未提供，无法审计
- 无 Web 服务器/php.ini 部署配置，无法确认对外暴露面与错误回显
- 无 composer.json 等依赖清单，无法评估第三方组件 CVE
- 无端点清单与路由信息，无法确认实际可达入口

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
| safety_guard | 安全防护 | 2.79 | 是 |
| surface_mapper | 攻击面测绘 | 5.0 | 是 |
| deep_finder | LLM 深挖 | 3.63 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 4.65 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
