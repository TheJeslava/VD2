# 落日二号乙漏洞挖掘报告 — 20261031-010522-84a6d5

- 生成时间：2026-10-30T17:05:45.581811+00:00
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

本次审计范围严格限定为单个 PHP 文件 049.php（约 20 行、356 字节），无框架、无路由、无端点清单。已去重的 findings 为空：没有任何类型被确认为漏洞，with_poc=0，即本次没有可交付的 POC（既无 HTTP POC，也无静态证据 POC）。最高危项无法确定——管线未识别到任何 sink 热点（sink_hot_files 为空），唯一热点是 049.php 第 3 行的请求参数读取（source）。这既可能是脚本确实无危险汇点，也可能是汇点写法未被规则覆盖（变量函数调用、动态方法名、include 变量等），因此不能据此判定无漏洞。surface_notes 提出的 5 个优先审计面（参数数据流、文件包含/路径拼接、命令执行、输出回显 XSS、配置类弱实现）均未被 findings 覆盖，全部转入人工复核。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 480 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次审计范围严格限定为 code_pack 中唯一文件 049.php（共 20 行，已全文通读）。该脚本仅做一件事：读取 $_GET['default']（第 4 行 array_key_exists + is_null 判断），进入 switch 白名单（第 7-17 行），仅允许 French/English/German/Spanish 四个字面量，其余任何取值走 default 分支执行 header("location: ?default=English") 后 exit。审计结论：1) 无 SQL/命令/文件/包含/反序列化/模板/SSRF 类 sink，全文件不存在 system/exec/include/fopen/echo 等危险调用；2) 白名单为严格字面量匹配（switch 使用 == 松散比较，但比较对象是字符串常量，PHP 8 下 '0'=='French' 之类不成立，且即使匹配失败也仅落入固定跳转），不存在绕过进入危险汇点的路径；3) 第 15 行 header 的 location 值为硬编码常量 "?default=English"，不含任何用户输入，不构成开放重定向或响应头注入（CRLF）；4) 无输出回显，无 XSS；5) 无 md5/sha1、无 rand/mt_rand、无 setcookie/session_set_cookie_params、无 mcrypt/openssl_encrypt、无 $_SERVER['HTTP_*'] 信任，medium_review_items 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 五类在该文件中均无对应代码，全部不成立；6) 源码与注释中未出现任何诱导性指令文本，无 prompt_injection 证据。该文件是典型的语言选择白名单示例（与 DVWA 类靶场片段一致），本身即为正确实现，无可申报 CVE 的漏洞。未闭合线索：无。未覆盖范围：code_pack 之外无其它文件（无 composer.json、无 Web 服务器配置、无 php.ini），因此无法评估部署路径、认证要求与运行时配置，但这些不影响本文件结论。

未覆盖 / 证据缺口：
- 无端点清单与部署配置，无法确认该文件真实 URL 路径与是否需要认证（不影响本文件无漏洞的结论）
- 无 php.ini / 服务器配置，无法评估运行时开关，但本文件未使用任何受此类配置影响的函数
- code_pack 仅含 1 个文件，无其它攻击面可审计

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
| safety_guard | 安全防护 | 2.97 | 是 |
| surface_mapper | 攻击面测绘 | 9.9 | 是 |
| deep_finder | LLM 深挖 | 4.35 | 是 |
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
