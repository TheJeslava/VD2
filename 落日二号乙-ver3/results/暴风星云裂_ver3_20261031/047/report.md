# 落日二号乙漏洞挖掘报告 — 20261031-010501-289970

- 生成时间：2026-10-30T17:05:21.508134+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\047.zip`
- 输入模式：`zip`
- SHA256：`3fb7cef196d058e1429319161506d9b7757247c40a8879ee94ca463b3d47eead`
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

本次汇总的 findings 为空（type_counts 为空，with_poc=0），没有任何已确认漏洞或 POC 交付。攻击面测绘显示 code_pack 仅含单文件 PHP 脚本 047.php（13 行、289 字节），无框架、无路由、无端点清单，047.php 被标为 source 热点（行 1）但 sink_hot_files 为空，说明输入入口存在而汇点未被自动识别；由于未提供代码正文，无法确认参数名、汇点与行号，最高危项无法判定。POC 不齐全（0 条），且本次无 HTTP POC 也无静态证据 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 378 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单文件 047.php（13 行），已逐行审计。该脚本在 POST 请求时维护 $_SESSION['last_session_id'] 自增计数，并通过 setcookie("dvwaSession", $cookie_value) 下发一个纯数字会话标识 Cookie。审计结论：(1) 无任何外部请求参数（$_GET/$_POST/$_COOKIE/$_REQUEST/$_SERVER 用户可控头）被读取并流入 SQL、命令、文件路径、include、eval、输出等汇点，不存在可闭合的注入/穿越/RCE 链；(2) 唯一外部输入面是 REQUEST_METHOD 的方法判断，不可控为攻击载荷；(3) setcookie 未设置 HttpOnly/Secure/SameSite 标志，且 Cookie 值为可预测的自增整数，属于 insecure_cookie / weak_random 类配置型弱点，但该脚本本身不基于此 Cookie 做任何鉴权或状态决策（会话状态仍由服务端 $_SESSION 维护），无法从本文件证明可导致会话劫持或越权，证据不足以构成 CVE 级发现，故不单独立项，仅作为线索记录；(4) 未出现 md5/sha1/DES/ECB/rand 等弱算法实现。未闭合线索：该文件疑似 DVWA 的弱会话 ID 练习页，实际风险取决于同站其它脚本是否信任 dvwaSession Cookie 做身份判定，而该部分代码不在 code_pack 内，按契约视为不存在，无法评估。

未覆盖 / 证据缺口：
- code_pack 仅含 047.php，无路由/认证/其它脚本，无法确认 dvwaSession Cookie 是否被其它组件用于鉴权
- 缺少 php.ini 与部署配置，无法评估 session 配置与 Cookie 标志的实际影响
- setcookie 缺少 HttpOnly/Secure/SameSite 及可预测自增 ID 属配置型弱点，但本文件内无对应鉴权汇点，链不闭合

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
| safety_guard | 安全防护 | 2.46 | 是 |
| surface_mapper | 攻击面测绘 | 6.74 | 是 |
| deep_finder | LLM 深挖 | 3.53 | 是 |
| candidate_screener | 候选筛选 | 3.1 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 4.18 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
