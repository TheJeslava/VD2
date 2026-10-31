# 落日二号乙漏洞挖掘报告 — 20261031-013640-ed1e9c

- 生成时间：2026-10-30T17:37:00.258438+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\001.zip`
- 输入模式：`zip`
- SHA256：`9eef8763d9327d2537ce1467f7f2014999c659dd40d8f76a19ca38fb07bdd6c9`
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

本次汇总的 findings 为空数组，type_counts 为空，with_poc=0，即没有任何已确认漏洞、也没有任何 POC 文本（既无 HTTP POC 也无静态证据 POC）。覆盖范围极小：仅 1 个 PHP 文件 001.php（20 行、1153 字节），无框架、无端点清单、无 source/sink 热点标注、无被隔离文件，因此不存在“最高危漏洞”可排序，也不存在 POC 齐全性可评估。surface_notes 指出该单文件是唯一可审计面，注入类与配置类风险均需在源码审计阶段逐行确认；由于 findings 未覆盖这些风险点，已全部转入 human_review，不能据此宣称该文件安全。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1277 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单个 PHP 文件 001.php（20 行），已逐行审计。该文件是一个纯静态的 HTML 说明页：第 3 行初始化 $message 后未再使用；第 5-18 行将一段固定字符串（含指向 openapi.yml 的链接与 DVWA API 使用说明）追加到未初始化的 $html 变量；第 20 行结束 PHP 块。文件中不存在任何外部输入读取（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER/$_FILES/php://input），不存在命令执行、SQL、文件读写、反序列化、模板、SSRF、重定向等危险汇点，也不存在哈希/加密/随机数/Cookie 标志位/信任边界判断等配置型风险点。因此没有任何可闭合的 source→sink 利用链，findings 为空。surface_notes 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 候选在源码中均无对应实现，属未命中而非误报。未覆盖范围：无 php.ini/Web 服务器配置/.htaccess、无 composer 依赖清单、无路由与端点信息、无版本历史，这些均不在 code_pack 内，按零工具契约视为不存在；001.php 引用的 openapi.yml 及 /vulnerabilities/api/v2/health/* 等 DVWA API 实现文件未送入本次 code_pack，无法审计，若后续需要评估这些 API 的真实漏洞，应将其源码纳入 code_pack 后重新审计。

未覆盖 / 证据缺口：
- openapi.yml 未在 code_pack 中，无法审计其描述的 API 契约
- DVWA /vulnerabilities/api/v2/health/* 等被引用接口的实现源码未提供
- 无 php.ini、Web 服务器配置、.htaccess，部署方式与错误回显未知
- 无 composer.json/lock，第三方依赖攻击面未知
- 无端点清单与路由信息，001.php 的实际 URL 与访问控制未知

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
| safety_guard | 安全防护 | 2.8 | 是 |
| surface_mapper | 攻击面测绘 | 6.47 | 是 |
| deep_finder | LLM 深挖 | 3.34 | 是 |
| candidate_screener | 候选筛选 | 2.34 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 4.74 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
