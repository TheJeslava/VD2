# 落日二号乙漏洞挖掘报告 — 20261031-005723-e3a298

- 生成时间：2026-10-30T16:57:40.403685+00:00
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

本次汇总的 findings 为空（type_counts 为空，with_poc=0），因此没有可交付的漏洞结论，也没有任何 POC（既无 HTTP POC，也无静态证据 POC）。覆盖统计显示仓库仅含 1 个 PHP 文件 004.php（17 行、292 字节），无框架、无端点清单、无 source/sink 热点标注、无隔离文件；输入未提供该文件的任何代码行，因此无法做行级审计，也无法给出文件内行号引用。最高危项无法判定：surface_notes 将 004.php 整体列为优先级 1 的待审计面，并点名 include/require、eval、system/exec/shell_exec/passthru、unserialize、file_get_contents/file_put_contents、header/Set-Cookie 等典型汇点，但这些均属待确认项，不是已确认漏洞。需强调：findings 为空是“本次未产出交付项”，不等于“该文件无漏洞”。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 401 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单文件 004.php（17 行），已逐行审计。该文件只做一件事：调用 dvwaCurrentUser() 与字符串 "admin" 比较，不相等则打印 Unauthorised、返回 403 并 exit。文件中不存在任何外部输入接收点（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER/$_FILES），也不存在任何危险汇点（无 include/require、eval、system/exec/shell_exec/passthru/proc_open、unserialize、file_get_contents/file_put_contents/fopen、header/setcookie、SQL 调用、模板渲染）。因此不存在可闭合的 source→sink 利用链，无法申报 CVE 级漏洞。注释中提到的 vulnerabilities/authbypass/change_user_details.php 不在 code_pack 内，按契约视为不存在，未做推断。dvwaCurrentUser() 的实现未提供，其返回值是否可被客户端影响（例如依赖可伪造的 Cookie/Session）无法确认，属未闭合线索，不单独立 finding。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 的定义未在 code_pack 中，无法判断其是否信任客户端可控的 Cookie/Session/Header，从而可能形成认证绕过；需在包含该函数定义的文件中复核。
- 注释引用的 vulnerabilities/authbypass/change_user_details.php 未提供，无法审计。
- 无 php.ini / Web 服务器配置 / .htaccess，无法评估 allow_url_include、register_globals 等运行时影响面。
- 无端点清单与部署信息，无法确认该脚本是否公网可达、是否有前置认证或 WAF。
- 无依赖清单，无法评估第三方组件 CVE。

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
| safety_guard | 安全防护 | 2.78 | 是 |
| surface_mapper | 攻击面测绘 | 6.2 | 是 |
| deep_finder | LLM 深挖 | 2.97 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.27 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
