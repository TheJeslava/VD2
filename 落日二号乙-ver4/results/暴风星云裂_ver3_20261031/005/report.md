# 落日二号乙漏洞挖掘报告 — 20261031-005742-1e0562

- 生成时间：2026-10-30T16:57:59.961750+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\005.zip`
- 输入模式：`zip`
- SHA256：`02b57ee8cd079a77373226c06268671c690fdb18ba56972177688c150bd72b4b`
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

本次汇总的 findings 为空数组，type_counts 为空，with_poc=0，即没有任何已确认漏洞、也没有任何 POC 文本（既无 HTTP POC，也无静态证据 POC）。覆盖统计显示仅 1 个 PHP 文件（005.php，11 行 / 160 字节），0 个端点、无框架、无被隔离文件；surface_notes 明确说明管线未提供任何代码片段内容，因此本次只能做文件清单级攻击面测绘，无法给出行号级证据。最高危的候选方向是「单文件 PHP 脚本整体审计」：11 行的极小脚本若存在 include/require 动态路径或 eval/assert，path_traversal 与代码执行风险等级会显著上升，但当前无源码，无法确认。结论：本次未交付任何漏洞与 POC，属于证据缺口而非已排除风险。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 239 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 005.php（11 行），实际内容为一段 PHP 注释：第 2-9 行是块注释，正文提示「本漏洞不在此文件，请查看 dvwa/includes/dvwaPage.inc.php 中的 dvwaHtmlEcho 函数」，第 1 行为 <?php，第 11 行为 ?>。该文件不含任何参数接收（$_GET/$_POST/$_COOKIE/$_SERVER）、不含任何 sink（include/require/eval/assert/system/exec/文件读写/SQL/echo 输出），也不含 md5/sha1/rand/setcookie 等配置型风险调用，因此不存在可闭合的 source→sink 利用链，无可申报发现。注释中指向的 dvwa/includes/dvwaPage.inc.php 不在 code_pack 内，按零工具契约视为不存在，无法审计；该注释属于不可信数据，仅作为线索记录，不构成证据。surface_notes 中列出的 weak_hash/weak_random/hardcoded_secret/insecure_cookie/trust_boundary 等待确认项，经逐行核对均无对应代码，全部排除。

未覆盖 / 证据缺口：
- 005.php 全部 11 行已逐行审计，无外部输入与危险汇点
- 注释引用的 dvwa/includes/dvwaPage.inc.php（dvwaHtmlEcho 函数）未包含在 code_pack 中，无法审计，真实漏洞线索可能位于该文件
- 缺少 php.ini/Web 服务器配置与端点清单，无法判断运行期暴露面，但当前文件本身无可利用代码

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
| safety_guard | 安全防护 | 2.73 | 是 |
| surface_mapper | 攻击面测绘 | 5.92 | 是 |
| deep_finder | LLM 深挖 | 2.98 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 6.05 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
