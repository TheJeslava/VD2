# 落日二号乙漏洞挖掘报告 — 20261031-172424-520de3

- 生成时间：2026-10-31T09:24:44.541094+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\004.zip`
- 输入模式：`zip`
- SHA256：`b9fab202b9a48529e59fc3b093ab407f0b2c3c52e487f6da9dfafce8e36fbfc5`
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

本次管线未交付任何已确认漏洞：findings 为空，type_counts 为空，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。覆盖范围极小，仅 1 个 PHP 文件 004.php（17 行、292 字节），endpoints=0、frameworks=[]、quarantined=[]，且输入未提供该文件的实际源码内容，只有路径/行数/大小元数据。因此本次无法对 command_injection / sql_injection / xpath_injection / ldap_injection / xss / path_traversal / ssrf 以及 weak_crypto / weak_hash / weak_random / insecure_cookie / trust_boundary / hardcoded_secret 中的任何一类给出基于代码的判断——这是覆盖缺口，不是“未发现漏洞”。最高危项无法排序：没有 findings 可供排序，唯一可确定的是 004.php 作为唯一可能的 HTTP 入口载体，应作为第一优先人工通读对象。POC 不齐全（0/0），且不存在可宣称可动态复现的条目。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 401 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次输入仅包含单个 PHP 文件 004.php（17 行），已全文审计。该文件只做一件事：调用 dvwaCurrentUser() 与字符串 "admin" 比较，不相等则打印 Unauthorised、返回 403 并 exit。文件内不存在任何外部输入取值（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER 读取）、无 echo/print 输出用户数据、无 include/require、无文件操作、无 system/exec/eval、无 SQL/模板/反序列化调用，因此不存在可闭合的 source→sink 污点链。注释中提到的 vulnerabilities/authbypass/change_user_details.php 不在 code_pack 内，按契约视为不存在，无法审计，也不能据此推断 004.php 存在认证绕过。dvwaCurrentUser() 的实现未提供，其返回值是否可被客户端影响（如依赖 Cookie 中的用户名）无法确认，属于未闭合线索而非可报告漏洞。配置类候选（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）在本文件中均无对应调用证据，不成立。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 的定义未在 code_pack 中，无法判断其是否信任客户端可控数据（如 Cookie/Header 中的用户名），这是唯一可能形成 auth_bypass 的未闭合线索
- 注释引用的 vulnerabilities/authbypass/change_user_details.php 未提供，无法审计
- 无端点清单与部署配置，无法确认该脚本的访问路径与鉴权前置条件
- 无框架/依赖信息，无法评估组件级 CVE

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
| safety_guard | 安全防护 | 4.01 | 是 |
| surface_mapper | 攻击面测绘 | 7.0 | 是 |
| deep_finder | LLM 深挖 | 3.19 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 6.27 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
