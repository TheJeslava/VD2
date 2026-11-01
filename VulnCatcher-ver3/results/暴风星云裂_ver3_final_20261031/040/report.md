# 落日二号乙漏洞挖掘报告 — 20261031-014255-7966b8

- 生成时间：2026-10-30T17:43:15.952807+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\040.zip`
- 输入模式：`zip`
- SHA256：`a7a3a902cbf51a117eedf45420f67900d6bd15338d9838b48c773e4175ce8254`
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

本次汇总的 findings 为空：type_counts 为空、with_poc=0，没有任何已确认漏洞或 POC 工件。覆盖统计显示仅 1 个 PHP 文件（040.php，53 行，约 1.4KB），无框架、无路由、endpoints=0，且未提供源码正文，因此无法给出任何带行号的漏洞结论。最高危的候选方向来自攻击面测绘：040.php 是唯一 sink 热点文件，注入类（command_injection / sql_injection / xpath_injection / ldap_injection / xss / path_traversal / ssrf）与文件路径操作、命令执行汇点都只能集中在该文件，但均未形成可交付 finding。POC 不齐全（0 条），且不存在可宣称动态复现的 HTTP POC；配置类（weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary）仅有静态复核线索，无静态证据 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1627 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 040.php 的 1-46 行（共 53 行，尾部 47-53 未送入）。该文件是 DVWA 的 SQL 注入练习页面片段：第 3-5 行从 $_SESSION['id'] 取值，第 10 行与第 28 行将其直接拼接进 SQL 语句，第 11 行 mysqli_query、第 31 行 SQLite query 执行。从根因看确实存在字符串拼接 SQL 注入（CWE-89），但污点源是 $_SESSION['id'] 而非请求参数，本 code_pack 中看不到任何写入 $_SESSION['id'] 的代码（该赋值应发生在未送入的其它 DVWA 文件中），因此 source→sink 链在本次可见范围内不闭合，无法证明外部攻击者可控该值。此外该文件属于 DVWA 故意脆弱教学靶场，非真实产品，不满足 CVE/赏金接收标准。第 20、44 行 $id 回显到 HTML 属反射型 XSS 面，同样受限于 source 不可控。配置类线索（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）在已展示的 1-46 行中均无对应代码，无法确认。综上按零容忍误报原则不交付 finding。未闭合线索：47-53 行内容未知；$_SESSION['id'] 的写入点不在 code_pack；无 php.ini/部署信息，无法确认可达性与 allow_url_include 等设置。

未覆盖 / 证据缺口：
- 040.php 第 47-53 行未送入 code_pack，未审计
- $_SESSION['id'] 的赋值/写入点不在 code_pack，SQL 注入污点源外部可控性无法证明
- 无路由/端点表，无法确认该页面 HTTP 可达性与参数名
- 无 php.ini、Web 服务器配置，无法评估运行时可利用性
- 项目为 DVWA 教学靶场，非真实产品，不满足 CVE 申报标准

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
| safety_guard | 安全防护 | 2.84 | 是 |
| surface_mapper | 攻击面测绘 | 8.93 | 是 |
| deep_finder | LLM 深挖 | 3.32 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.35 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
