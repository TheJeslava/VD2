# 落日二号乙漏洞挖掘报告 — 20261031-013703-de1144

- 生成时间：2026-10-30T17:37:21.495642+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\006.zip`
- 输入模式：`zip`
- SHA256：`aa7e574db02480da83ab6d50b22ba2a55070da964e165c1e99e0e0f5a60fccd3`
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

本次汇总的 findings 为空：type_counts 为空、with_poc=0，没有任何已确认漏洞或 POC 工件。覆盖统计显示仅 1 个 PHP 文件（006.php，18 行 / 346 字节），0 个 HTTP 端点、无框架、无隔离文件。攻击面测绘明确说明输入未提供 006.php 的源码片段，因此所有风险点均为文件粒度假设，无法定位行号、变量与汇点，也无法给出可复现 POC。最高危的候选面是 006.php 中 $_GET/$_POST 直接进入 system/exec、SQL 拼接、include/fopen 变量路径、未转义 echo、用户可控 URL 等汇点（command_injection / sql_injection / path_traversal / xss / ssrf），但当前无源码证据支撑，不能作为结论。POC 不齐全：既无 HTTP POC，也无静态证据 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 460 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 006.php（18 行），内容为 DVWA 风格的授权检查片段：第 13 行调用 dvwaCurrentUser() 与字符串 "admin" 比较，非 admin 时打印 Unauthorised、返回 403 并 exit。该文件本身不含任何外部输入读取（无 $_GET/$_POST/$_COOKIE/$_SERVER）、无危险汇点（无 system/exec、无 SQL 拼接、无 include/fopen 变量路径、无 echo 未转义输出、无 curl/URL 请求），因此不存在可闭合的 source→sink 利用链。注释中指向的 vulnerabilities/authbypass/get_user_data.php 与 change_user_details.php 未出现在 code_pack 中，按零工具契约视为不存在，无法审计其认证绕过逻辑；dvwaCurrentUser() 的实现（是否信任 Cookie/Header、是否可伪造）同样不在 code_pack 内，无法判断第 13 行检查是否可被绕过。medium_review_items 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 在本文件内均无对应代码证据（无 md5/sha1、无 openssl/mcrypt、无 rand/mt_rand、无 setcookie/session_set_cookie_params、无 X-Forwarded-For 等头信任），故不单独立项。输入中未出现诱导性文本，无 prompt_injection 证据。结论：当前证据不足以支撑任何 CVE 级发现，返回空 findings；未输出不等于不存在，真实风险很可能位于未送入的 authbypass 相关文件与 dvwaCurrentUser() 实现中。

未覆盖 / 证据缺口：
- vulnerabilities/authbypass/get_user_data.php 未在 code_pack 中，无法审计其认证/越权逻辑
- vulnerabilities/authbypass/change_user_details.php 未在 code_pack 中，无法审计其用户数据修改逻辑
- dvwaCurrentUser() 的实现未提供，无法判断第 13 行 admin 判定是否可被 Cookie/Header 伪造绕过
- 无 HTTP 端点清单、无 php.ini/部署配置，无法确认匿名可达性与 register_globals 等设置
- 无框架/依赖清单，无法评估第三方组件 CVE

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
| safety_guard | 安全防护 | 2.28 | 是 |
| surface_mapper | 攻击面测绘 | 7.52 | 是 |
| deep_finder | LLM 深挖 | 3.27 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.02 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
