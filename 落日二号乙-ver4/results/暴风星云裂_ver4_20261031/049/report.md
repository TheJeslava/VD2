# 落日二号乙漏洞挖掘报告 — 20261031-164757-05ecd1

- 生成时间：2026-10-31T08:48:18.439531+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\049.zip`
- 输入模式：`zip`
- SHA256：`275c9aa49fd32c5baf3a69c1b9199d20f6edf4b8d28cdf1a0598ae6adf1e2b16`
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

本次汇总的 findings 为空数组，type_counts 为空，with_poc=0，即没有任何已去重的漏洞条目可供交付，也没有二次注入链。覆盖统计显示仅 1 个 PHP 文件（049.php，20 行、356 字节），无框架、无端点清单、无隔离文件；surface_notes 只把 049.php 第 3 行标为 source 热点，未识别到任何 sink 热点，因此 source 到 sink 的连通性尚未建立。最高危的候选方向是第 3 行请求参数的下游数据流（可能流向 include/require、echo、SQL 拼接、文件操作或 system/exec/eval），但当前仅为攻击面排序，不构成漏洞结论。POC 方面：无 HTTP POC，也无静态证据 POC，POC 不齐全。需强调：findings 为空是“未交付”，不是“已确认无漏洞”。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 480 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 049.php（共 20 行，已完整展示 1-20 行）。该脚本读取 $_GET['default']（第 4 行），经 switch 白名单（第 7-17 行）仅允许 French/English/German/Spanish，其余值走 default 分支执行 header("location: ?default=English") 并 exit。审计结论：1) 不存在 SQL/命令/代码/文件包含/反序列化等 sink，全文无 include/require/system/exec/eval/文件操作/数据库调用；2) 无 echo/print 输出用户输入，不构成反射型 XSS；3) 重定向目标为硬编码常量 "?default=English"，用户输入未进入 Location 头，不构成开放重定向；4) 无 md5/sha1/rand/mt_rand/setcookie/session 相关调用，weak_hash/weak_crypto/weak_random/insecure_cookie 均无证据；5) 无信任 X-Forwarded-* 等头字段的逻辑。该文件是典型的语言选择白名单示例，未发现可闭合的 source→sink 利用链，故 findings 为空。未覆盖范围：无 php.ini/Web 服务器配置/composer.json，无法确认运行环境与危险函数禁用情况；无端点清单，无法确认 049.php 实际访问路径与认证要求；无版本与提交历史。以上均为证据缺口，不代表不存在漏洞。

未覆盖 / 证据缺口：
- 无 php.ini / Web 服务器配置 / .htaccess，无法确认运行环境与 disable_functions 等限制
- 无端点清单，无法确认 049.php 的访问路径、认证要求与公网暴露面
- 无 composer.json 依赖清单与版本信息，无法关联已知 CVE
- 无提交历史，无法判断补丁状态

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
| safety_guard | 安全防护 | 2.64 | 是 |
| surface_mapper | 攻击面测绘 | 8.96 | 是 |
| deep_finder | LLM 深挖 | 3.11 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.81 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
