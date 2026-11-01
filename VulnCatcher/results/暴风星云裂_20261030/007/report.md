# 落日二号乙漏洞挖掘报告 — 20261030-224546-61affc

- 生成时间：2026-10-30T14:46:07.717100+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\007.zip`
- 输入模式：`zip`
- SHA256：`47dd7bdea9f850e88c4cbae3c23033d77110b56a050bbf68a7168677faa9d18f`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`high`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总的 findings 为空：type_counts 为空、with_poc=0，没有任何已确认漏洞或 POC 工件。覆盖统计显示仅 1 个 PHP 文件（007.php，110 行，约 5KB），无框架、无已登记 HTTP 端点、无隔离文件；surface_notes 明确说明输入只给了文件清单与热点计数（source 热点 7 处、sink 热点 2 处，均在 007.php），未提供任何代码行、路由或配置，因此所有攻击面判断均为 llm_inferred 形态推断，不构成漏洞结论。最高危的候选方向是 007.php 内 7 处取参热点到 2 处危险汇点的污点链路（优先命令执行/代码执行与文件操作类汇点），但当前无代码证据支撑，无法定级。POC 不齐全：既无 HTTP POC，也无静态证据 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 5770 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 007.php（1-110 行，DVWA 风格的越权/访问控制练习脚本）。逐行追踪结果：所有数据库访问均使用 mysqli_prepare + bind_param（第 7-17、28-34、45-63、95-99 行），未发现 SQL 拼接注入；$_GET['user_id'] 在第 22 行经 /^\d+$/ 白名单校验并在第 25 行 intval 转换，无法承载注入或路径穿越；第 56-59 行输出均经 htmlspecialchars(ENT_QUOTES,'UTF-8') 编码，无反射型 XSS；第 92 行虽信任 HTTP_X_FORWARDED_FOR 作为日志 IP，但该值仅经 bind_param 写入 bac_log.ip_address，不参与任何权限判断或危险汇点，属日志伪造/审计污染，未达到 high 档且不构成可申报 CVE 的闭合链；第 40-43 行的会话校验（$id == $session_id）与第 107-109 行的会话初始化存在注释所称的 session fixation 隐患，但 code_pack 中没有任何 session_start/session_regenerate_id/登录流程代码，无法确认会话如何被攻击者预置，链路不闭合，故不报告。未发现命令执行、代码执行、文件包含、反序列化、SSRF、XXE、模板注入等 sink（surface_notes 声称的 2 处 sink 热点在本文件中对应的是 mysqli_query 的 SHOW TABLES/CREATE TABLE 固定语句，无外部输入）。配置类线索（weak_hash/weak_crypto/weak_random/insecure_cookie/hardcoded_secret）在可见 110 行内均未出现 md5/sha1/rand/setcookie/硬编码口令，故无候选。结论：本文件在当前证据下不存在满足 min_severity=high、min_confidence=0.6 的可闭合漏洞，返回空 findings。

未覆盖 / 证据缺口：
- code_pack 仅含 007.php 的 1-110 行，未提供 dvwaCurrentUser()、session_start()、$GLOBALS['___mysqli_ston'] 初始化及登录/会话建立代码，session fixation 与越权链无法闭合
- 无路由/端点定义，无法确认该脚本的实际可达 URL、认证前置与部署形态
- 无 php.ini / Web 服务器配置，无法评估 register_globals、错误回显、目录权限
- 无 composer.json 等依赖清单，无法评估第三方组件 CVE
- HTTP_X_FORWARDED_FOR 仅用于日志写入（第 92、97 行），属审计日志伪造，未达 high 档，未单独立项

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
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.66 | 是 |
| surface_mapper | 攻击面测绘 | 7.91 | 是 |
| deep_finder | LLM 深挖 | 4.59 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.02 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
