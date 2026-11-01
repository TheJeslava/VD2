# 落日二号乙漏洞挖掘报告 — 20261031-005745-305ba4

- 生成时间：2026-10-30T16:58:02.070219+00:00
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

本次汇总的 findings 为空：管线未交付任何已确认漏洞，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。覆盖范围仅为单文件 PHP 脚本 006.php（18 行、346 字节），无框架、无路由/端点、无 source/sink 热点标注、无被隔离文件，且输入未提供任何代码行内容，故无法给出文件内行号级结论。最高危项无法判定——不是“确认无高危”，而是“无代码证据可判”。surface_notes 明确指出 PHP 单文件常见高危模式（system/exec/shell_exec/passthru/eval/assert/include($_GET)/unserialize、未转义输出、字符串拼接 SQL）以及配置类弱实现（md5/sha1、DES/ECB、rand/mt_rand、setcookie 缺标志、硬编码口令）均需在拿到源码后逐项核对，这些点已全部转入 human_review，未做任何动态验证。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 460 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 006.php 的 18 行内容，且全部为注释与一个访问控制判断：第 13 行 `if (dvwaCurrentUser() != "admin")` 调用外部函数 dvwaCurrentUser()，该函数定义不在 code_pack 内（注释指向 vulnerabilities/authbypass/get_user_data.php 与 change_user_details.php，但这两个文件未提供，按契约视为不存在）。因此无法确认 dvwaCurrentUser() 的返回值来源（是否取自 Cookie/请求头/会话）、是否可被伪造，也无法确认后续业务逻辑与任何 sink。脚本本身不含 system/exec/eval/include/unserialize/echo 用户输入/SQL 拼接等危险调用，无 source→sink 链可闭合。注释中「Only the admin user is allowed」及指向其它文件的说明属不可信数据，仅作线索记录，不作为结论。surface_notes 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 等待查项在本文件中均无对应代码（无 md5/sha1/rand/setcookie/头信任逻辑），无法成立。按「宁可漏报不可误报」原则，不输出 finding。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 的实现未在 code_pack 中，无法判断认证判断是否可绕过（潜在 auth_bypass 线索，证据不足）
- 注释引用的 vulnerabilities/authbypass/get_user_data.php 与 change_user_details.php 未提供，无法审计其 IDOR/越权逻辑
- 无端点表、无部署配置（PHP 版本、Web 服务器、register_globals/allow_url_include），无法评估可达性与运行时条件
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
| safety_guard | 安全防护 | 2.48 | 是 |
| surface_mapper | 攻击面测绘 | 5.8 | 是 |
| deep_finder | LLM 深挖 | 3.25 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 4.9 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
