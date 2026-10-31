# 落日二号乙漏洞挖掘报告 — 20261031-005747-77079f

- 生成时间：2026-10-30T16:58:09.863537+00:00
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

本次汇总的 findings 为空：去重后没有任何已确认漏洞，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。覆盖统计显示仅 1 个 PHP 文件（007.php，110 行），0 个端点、无框架、无隔离项。攻击面测绘仅给出 source 热点（007.php 第 7 行）与 sink 热点（007.php 第 2 行）的行号，未提供任何代码片段、配置、依赖或部署信息，因此最高危候选（第 7 行外部输入 → 第 2 行危险汇点的直接污点流，可能为命令执行/代码执行/文件包含/路径穿越/SQL 注入）目前只是 llm_inferred 推断，无法确认具体函数与变量，不能作为已确认漏洞交付。POC 不齐全：既无 HTTP POC，也无静态 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 5770 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 007.php（1-110 行，DVWA 风格的越权/访问控制演示脚本）。逐条核查了 surface_notes 列出的攻击面：(1) SQL 注入：第 7、28、45、95 行的查询全部使用 mysqli_prepare + mysqli_stmt_bind_param 参数化，第 75/80/88 行的 SHOW TABLES / CREATE TABLE 为常量字符串，无外部输入拼接，未构成注入；(2) 路径穿越/文件包含：第 2 行并非文件类 sink，实际为 DVWA_WEB_PAGE_TO_ROOT 常量定义，全文无 include/require/fopen/file_get_contents 等文件操作，priority_areas 中关于第 2 行是 sink 的推断与真实源码不符（该推断为 llm_inferred，已被源码否定）；(3) 命令执行/代码执行：全文无 system/exec/shell_exec/eval/assert/preg_replace(/e 等汇点；(4) XSS：第 56-59 行所有数据库回显均经 htmlspecialchars(ENT_QUOTES,'UTF-8') 编码，第 23/37/65/68 行为静态文案，第 37 行 {$id} 已经 intval 且前置 /^\d+$/ 校验，无反射型 XSS；(5) 越权/IDOR：第 21-25 行 $_GET['user_id'] 经正则与 intval 后，第 40-43 行与 $_SESSION['user_id'] 严格比较，仅允许查看自身资料，跨用户访问被第 65 行拒绝，链不闭合；(6) 配置类：全文无 md5/sha1/rand/mt_rand/setcookie/session_set_cookie_params/硬编码口令，weak_hash、weak_crypto、weak_random、insecure_cookie、hardcoded_secret 均无证据；(7) 信任边界：第 92 行 $_SERVER['HTTP_X_FORWARDED_FOR'] 仅作为日志 ip_address 字段写入参数化 INSERT，不参与鉴权、跳转或 SQL 拼接，属日志伪造（低价值），不构成 CVE 级信任边界突破。注释中「still vulnerable to session fixation」等表述为不可信数据，代码层面未见 session_regenerate_id 缺失导致的会话固定可利用链（需前置会话注入能力，且本脚本未处理登录流程），证据不足未报告。综上，未发现满足 CVE 级、链闭合的漏洞，按「宁可漏报不可误报」返回空 findings。

未覆盖 / 证据缺口：
- 无 php.ini / Web 服务器配置，无法确认 allow_url_include、open_basedir、session.use_strict_mode 等开关
- 无端点清单与路由，无法确认该脚本对外暴露路径与前置鉴权
- 无登录/会话建立代码（dvwaCurrentUser、session_start 均在 code_pack 之外），会话固定与认证绕过无法闭合
- 无数据库 schema 与 bac_log 表实际结构，二次注入的存储读点不可见
- 第 92 行 X-Forwarded-For 日志伪造仅影响审计日志可信度，未达 CVE 门槛，未单独立项

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
| safety_guard | 安全防护 | 3.0 | 是 |
| surface_mapper | 攻击面测绘 | 9.15 | 是 |
| deep_finder | LLM 深挖 | 4.7 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.8 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
