# 落日二号乙漏洞挖掘报告 — 20261031-214029-73d66d

- 生成时间：2026-10-31T13:40:56.723149+00:00
- 输入：`$WORKSPACE\暴风星云裂\007.zip`
- 输入模式：`zip`
- SHA256：`47dd7bdea9f850e88c4cbae3c23033d77110b56a050bbf68a7168677faa9d18f`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.5.0-ver5
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总的 findings 为空（type_counts 为空，with_poc=0），没有任何已确认漏洞或 POC 交付。覆盖统计显示仅 1 个 PHP 文件（007.php，110 行，约 5KB），endpoints=0、frameworks=[]、quarantined=[]，说明攻击面测绘只拿到文件清单与热点统计（source 热点≈第 7 行、sink 热点≈第 2 行），未提供任何代码片段、配置、依赖或路由信息，因此无法完成 source→sink 数据流确认，也无法给出最高危结论。surface_notes 提出的 5 个优先审计区（参数到危险汇点链路、文件包含/路径拼接、命令执行汇点、输出回显 XSS、配置/实现类风险）均未被 findings 覆盖，全部转入人工复核。POC 方面：既无 HTTP POC，也无静态证据 POC，不能宣称任何漏洞可动态复现。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 5770 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 007.php（1-110 行，DVWA 风格的 BAC 示例脚本）。逐行核对后未发现可闭合的 CVE 级利用链：(1) 第 7-17 行按当前用户查询 user_id/role 使用 mysqli_prepare + bind_param，无拼接；(2) 第 21-25 行 $_GET['user_id'] 先经 /^\d+$/ 白名单校验再 intval，第 28-34 行存在性检查、第 45-49 行资料查询、第 95-98 行日志写入全部为参数化语句，SQL 注入链不成立；(3) 第 56-59 行输出均经 htmlspecialchars(ENT_QUOTES,'UTF-8')，反射型 XSS 不成立；(4) 无 include/require、无文件读写、无 system/exec/shell_exec/passthru/popen/反引号、无 unserialize、无模板渲染、无 curl/file_get_contents，命令注入、代码执行、路径穿越、SSRF、反序列化、SSTI 均无 sink；(5) 第 43 行 $id == $session_id 的归属校验在服务端完成，越权读取他人资料被阻断，不构成 IDOR。未闭合线索（证据不足，未单独立项）：a) 第 40-43 行依赖 $_SESSION['user_id']，第 107-109 行在会话缺失时用当前登录用户 ID 初始化，若上游存在会话固定/会话未及时轮换，理论上可影响归属判断，但会话生成与轮换逻辑不在 code_pack 内，无法确认；b) 第 92 行直接信任 HTTP_X_FORWARDED_FOR 作为日志 IP，属 trust_boundary 弱化，仅影响审计日志真实性，无权限/数据影响，未达 CVE 门槛；c) 第 75-88 行动态 SHOW TABLES / CREATE TABLE 使用固定字符串，无外部输入，不构成注入；d) 第 100-102 行 catch(Exception) 对 mysqli 错误（PHP 7 下多为 Error/Warning 而非 Exception）可能不生效，属健壮性问题。code_pack 之外无其它文件（file_count=1），无配置、依赖、路由与认证中间件信息，故认证机制、php.ini 开关（allow_url_include、open_basedir）、部署与前置 WAF 均无法评估。输入中未出现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- 无 php.ini / Web 服务器配置，无法判断 allow_url_include、register_globals、open_basedir 等开关
- 无会话生成与轮换代码，无法确认 session fixation 是否可实际利用
- 无端点/路由清单与认证中间件，无法确认脚本实际可访问路径与前置过滤
- 无 composer.json 与第三方依赖信息
- 无数据库 schema 与 users 表数据，无法评估 avatar 等字段的存储型风险

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
| `blind_sql_injection` | CWE-89 |  | 0 |
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
| safety_guard | 安全防护 | 3.69 | 是 |
| surface_mapper | 攻击面测绘 | 10.11 | 是 |
| deep_finder | LLM 深挖 | 5.92 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 7.0 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
