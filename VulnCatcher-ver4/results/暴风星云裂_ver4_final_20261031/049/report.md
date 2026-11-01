# 落日二号乙漏洞挖掘报告 — 20261031-173331-b20e22

- 生成时间：2026-10-31T09:33:47.949436+00:00
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

本次汇总的 findings 为空：去重后没有任何已确认漏洞，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。覆盖统计显示仅 1 个 PHP 文件（049.php，20 行），0 个端点、无框架、无隔离文件。攻击面测绘只标出 049.php 第 3 行一个 source 热点（外部输入读取），未提供任何 sink 热点，也未提供该文件源码内容，因此无法沿数据流判断是否汇入命令执行、SQL、文件路径、输出等危险汇点。最高危项无法排序——当前没有可定级的 finding；唯一需要关注的是 049.php 第 3 行输入读取点的后续流向，以及 trust_boundary 语义，二者均需人工复核。POC 不齐全（0/0），且因缺少源码与 sink 证据，现阶段也无法产出可信 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 480 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单个 PHP 文件 049.php（20 行，完整展示 1-20 行）。已逐行审计：第 4 行通过 array_key_exists("default", $_GET) 与 !is_null 读取外部参数 default，第 7 行 switch 对其做严格值匹配（PHP switch 使用松散比较 ==，但此处 case 均为字符串字面量 French/English/German/Spanish，未匹配时进入 default 分支）。第 15 行 header("location: ?default=English") 为重定向，目标为硬编码常量字符串，未拼接任何用户输入，因此不构成开放重定向或 CRLF 头注入（用户输入不进入 header 值）。脚本中不存在 echo/print 等输出汇点、无 SQL/命令/文件/反序列化/模板/SSRF 相关调用，无 Cookie/session/加密/随机数代码，故 XSS、SQLi、命令注入、路径穿越、SSRF、弱加密/弱哈希/不安全 Cookie 等类型均无证据。唯一理论上的松散比较风险（如 default=0 时 PHP 8 之前 '0'=="French" 为 false，实际不会命中任何 case，仍走 default 分支）不产生安全影响。结论：该文件未发现可闭合的 source→sink 利用链，不满足 CVE 级发现标准，返回空 findings。未覆盖范围：无端点清单、无 Web 服务器/php.ini 配置、无 include 关系、无依赖信息，无法评估部署层与组件级问题；这些缺口不影响本文件本身的结论。

未覆盖 / 证据缺口：
- 无端点清单，无法确认该脚本的实际路由与可达性
- 无 php.ini / Web 服务器配置，无法确认 register_globals 等运行环境
- 无 include/自动加载关系，无法确认是否被其他脚本以不同上下文包含
- 无依赖与第三方库信息，无法评估组件级 CVE
- 无认证/session 相关代码，trust_boundary 与 insecure_cookie 无法进一步确认（但本文件内亦无相关写入点）

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
| safety_guard | 安全防护 | 2.75 | 是 |
| surface_mapper | 攻击面测绘 | 5.27 | 是 |
| deep_finder | LLM 深挖 | 4.06 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 4.55 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
