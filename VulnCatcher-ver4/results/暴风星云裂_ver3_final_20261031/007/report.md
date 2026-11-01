# 落日二号乙漏洞挖掘报告 — 20261031-013709-6eb5f5

- 生成时间：2026-10-30T17:37:28.603413+00:00
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

本次汇总的 findings 为空：攻击面测绘阶段只识别出 1 个 PHP 文件（007.php，110 行），未产出任何已确认漏洞，也没有 POC（with_poc=0）。测绘给出的最高优先级线索是 007.php 内 source 热点（第 7 行）与 sink 热点（第 2 行）同处一个文件、行距很近，提示参数读取后几乎无校验即进入危险汇点，可能承载 command_injection / sql_injection / path_traversal / ssrf / 反射型 xss 等注入类问题；但这只是攻击面推断，尚未经源码逐行审读确认，不能作为漏洞结论。配置型候选（weak_hash / weak_crypto / weak_random / insecure_cookie）同样只有待查线索，无算法或标志位证据。由于 findings 为空，本次没有任何可交付 POC，既无 HTTP POC 也无静态证据 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 5770 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 007.php（1-110 行，DVWA 风格的越权/日志演示页面）。逐行还原了数据流：第 21 行读取 $_GET['action'] 与 $_GET['user_id']，第 22 行用 /^\d+$/ 白名单校验，第 25 行 intval 强转，随后第 28-34 行、第 45-49 行、第 95-99 行全部使用 mysqli_prepare + bind_param 参数化查询，未发现 SQL 拼接；第 56-59 行输出均经 htmlspecialchars(ENT_QUOTES,'UTF-8') 编码，未发现反射型 XSS；第 92 行读取 HTTP_X_FORWARDED_FOR 仅作为字符串绑定进日志表，不构成注入或信任边界突破（最多是日志伪造，不达 CVE 级别）。第 40-43 行的会话校验（$id == $session_id）在服务端完成，越权访问被拒绝；第 107-109 行仅在会话缺失时写入 user_id，未接受客户端提供的会话标识，不构成会话固定。未发现命令执行、文件包含/路径穿越、反序列化、SSRF、模板注入等 sink。surface_notes 中提到的 source 第 7 行/sink 第 2 行热点与实际代码不符（第 2 行是常量定义，第 7 行是参数化 SQL 字符串），属于测绘阶段的启发式误标，不构成证据。未闭合线索：无 composer/包含清单，无法确认是否存在被 include 的公共函数文件；无 Web 服务器配置，无法确认 007.php 的访问路径与认证要求；无数据库配置，无法评估日志表创建失败时的行为。以上均不影响本文件内已闭合的“无高危链”结论。

未覆盖 / 证据缺口：
- 无 include/require 依赖清单，无法确认是否存在被引入的第三方库或公共函数文件
- 无 Web 服务器配置与 URL 重写规则，无法确认 007.php 实际访问路径与是否需认证
- 无数据库连接配置与 PHP 运行环境（disable_functions/open_basedir），无法评估日志写入失败与文件操作影响面
- surface_notes 标注的 source 第 7 行 / sink 第 2 行热点与真实代码语义不符，测绘结论未能在源码层复现

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
| safety_guard | 安全防护 | 2.53 | 是 |
| surface_mapper | 攻击面测绘 | 8.15 | 是 |
| deep_finder | LLM 深挖 | 3.71 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.16 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
