# 落日二号乙漏洞挖掘报告 — 20261031-011441-faa3e5

- 生成时间：2026-10-30T17:15:07.177466+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\007.zip`
- 输入模式：`zip`
- SHA256：`47dd7bdea9f850e88c4cbae3c23033d77110b56a050bbf68a7168677faa9d18f`
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

本次汇总的 findings 为空数组，type_counts 为空，with_poc=0，即没有任何已确认漏洞、也没有任何 POC 文本（既无 HTTP POC，也无静态证据 POC）。覆盖统计显示仅 1 个 PHP 文件（007.php，110 行，约 5KB），endpoints=0，无框架、无依赖清单、无配置与会话信息。攻击面测绘指出 source 热点在 007.php:7、sink 热点在 007.php:2，二者同文件且行距极短，理论上存在从请求参数到危险汇点的短污点链，但该链路尚未被任何 finding 证实，属未验证推断。最高危的候选方向是第 2 行若为 system/exec/eval/include 且参数来自第 7 行请求取值，则可能构成命令执行/代码执行/文件包含；其次为 SQL 拼接、反序列化、路径穿越。由于 findings 为空，本次不宣称存在任何已确认漏洞，也不宣称不存在——所有方向均需人工按代码逐行复核。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 5770 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 007.php（110 行，DVWA 风格的越权/会话固定演示脚本）。已逐行审计：第 7-17 行使用 mysqli_prepare + bind_param 查询当前用户，无注入；第 21-25 行对 $_GET['user_id'] 先做 /^\d+$/ 正则再做 intval，随后第 28-34 行以整型绑定参数查询存在性，第 45-49 行同样参数化查询资料，SQL 注入链不成立；第 56-59 行输出均经 htmlspecialchars(ENT_QUOTES,'UTF-8')，XSS 链不成立；第 92 行 $_SERVER['HTTP_X_FORWARDED_FOR'] 仅作为日志 ip_address 以 's' 绑定参数写入 bac_log，不参与鉴权、跳转或 SQL 拼接，属可伪造日志字段，未构成可申报的信任边界漏洞；第 95-99 行日志插入为参数化。真正的逻辑缺陷在第 40-43 行：仅比较 $_GET['user_id'] 与 $_SESSION['user_id']，而第 107-109 行在会话缺失时用当前登录用户 ID 初始化会话，脚本本身未提供任何会话建立/固定入口（无 session_start、无 setcookie、无登录流程），无法在 code_pack 内闭合“攻击者如何从外部控制或固定 $_SESSION['user_id'] 以读取他人资料”的利用链，故按零容忍误报原则不单独立项，仅作为线索记录。未发现命令执行、文件包含、反序列化、SSRF、文件上传、硬编码密钥、弱哈希/弱随机/不安全 Cookie 等汇点（文件内无 system/exec/eval/include/unserialize/md5/rand/setcookie 调用）。覆盖缺口：无 php.ini/.htaccess、无 composer 依赖、无路由与认证配置、无 session_start 所在的上层包含文件（DVWA 主流程），因此会话固定与越权读取的实际可利用性无法确认；code_pack 之外文件视为不存在。

未覆盖 / 证据缺口：
- 缺少 session_start 及会话初始化所在的上层文件，无法确认 $_SESSION['user_id'] 是否可被攻击者固定或篡改（第 40-43 行越权判断依赖该前提）
- 无 php.ini/.htaccess/Web 服务器配置，无法确认 allow_url_include、display_errors 等开关
- 无认证/登录流程代码，无法判断未授权访问与角色边界
- 无数据库 schema，bac_log 表结构与 users 表字段仅从 SQL 推断
- endpoints 为空，请求方法（GET/POST）与参数面由 007.php 第 21 行反推

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
| safety_guard | 安全防护 | 2.58 | 是 |
| surface_mapper | 攻击面测绘 | 12.16 | 是 |
| deep_finder | LLM 深挖 | 4.49 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 6.59 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
