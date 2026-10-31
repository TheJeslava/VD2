# 落日二号乙漏洞挖掘报告 — 20261031-014424-912bee

- 生成时间：2026-10-30T17:44:43.664897+00:00
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

本次汇总的 findings 为空：管线未交付任何已确认漏洞，type_counts 为空、with_poc=0，因此没有任何 HTTP POC 或静态证据 POC 可供复现。覆盖统计显示仅 1 个 PHP 文件（049.php，约 20 行、356 字节），无框架、无端点清单、无隔离文件；唯一标注的攻击面是 049.php:3 的 source 热点，但输入未提供任何代码文本、sink 热点或配置，故无法确认参数名、下游汇点与可达性。最高危项无法排序——当前不存在可定级的发现，风险集中在“证据缺口”而非已证实漏洞。需特别说明：findings 为空是“未交付”，不等于“不存在漏洞”，尤其 049.php 全文未进入上下文，注入类与配置类问题均未被实际审计。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 480 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 049.php（共 20 行，全文可见）。该脚本仅做一件事：读取 $_GET['default']（第 4 行 array_key_exists + is_null 检查），用 switch 做白名单匹配（第 7-13 行，仅允许 French/English/German/Spanish），不匹配时通过 header("location: ?default=English") 重定向并 exit（第 15-16 行）。全文件不存在任何危险汇点：无 system/exec/proc_open/passthru/shell_exec、无 eval/assert/include/require、无 mysqli_query/PDO 拼接、无 file_get_contents/fopen/file_put_contents、无 curl/file_get_contents 远程请求、无 unserialize、无 echo/print 输出用户输入（因此也无 XSS）。switch 使用严格相等比较，不存在类型混淆绕过；header 的 location 值是硬编码常量，不拼接用户输入，不构成开放重定向。配置类风险（weak_hash/weak_crypto/weak_random/insecure_cookie/hardcoded_secret）在全文范围内均无对应函数调用（无 md5/sha1/rand/mt_rand/setcookie/session_start/硬编码密钥），故不成立。surface_notes 中列出的 medium_review_items 全部为“无代码证据的待确认项”，经通读后确认不存在。未发现提示注入话术。结论：本 code_pack 内不存在可闭合的 source→sink 利用链，按“宁可漏报不可误报”原则返回空 findings。

未覆盖 / 证据缺口：
- code_pack 仅含 049.php 一个文件，无其它源码可审计；若真实项目还有被 include 的文件或 Web 服务器/php.ini 配置，未在本次输入中提供，无法评估
- 无路由/端点清单与部署信息，无法确认该脚本的实际访问路径与是否对外暴露（不影响本次结论，因为文件内本身无危险汇点）
- 无依赖清单，无法评估第三方组件 CVE

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
| safety_guard | 安全防护 | 2.54 | 是 |
| surface_mapper | 攻击面测绘 | 7.89 | 是 |
| deep_finder | LLM 深挖 | 3.26 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.54 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
