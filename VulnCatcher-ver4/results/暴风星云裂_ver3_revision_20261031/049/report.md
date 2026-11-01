# 落日二号乙漏洞挖掘报告 — 20261031-012228-82151c

- 生成时间：2026-10-30T17:22:45.990573+00:00
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

本次汇总的 findings 为空：去重后没有任何漏洞条目，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。攻击面测绘显示，全仓只有 1 个 PHP 文件（049.php，20 行），其中第 3 行被标记为 source 热点，但输入未提供该文件的源码片段，也没有 sink 热点、端点清单、配置文件或依赖清单。最高危的候选方向是 049.php:3 的外部输入是否流向 include/require、echo、file_* 或 exec/system，但当前证据不足以形成结论，只能列为人工复核项。POC 不齐全（0/0），且不存在可交付的复现文本。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 480 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已通读 code_pack 中唯一文件 049.php（共 20 行，未截断）。该脚本仅做一件事：读取 $_GET['default']（第 4 行 array_key_exists + is_null 判断），用 switch 白名单（第 7-17 行）只允许 French/English/German/Spanish，其余值走 default 分支执行 header("location: ?default=English") 后 exit。审计结论：1) 无 sink——不存在 include/require/eval/echo/print/exec/system/popen/fopen/file_get_contents/unserialize 等危险调用，输入值只参与 switch 相等比较，不进入任何拼接或输出；2) 无 SQL、无文件操作、无反序列化、无命令执行、无模板；3) 第 15 行的 header 重定向目标为硬编码常量字符串 "?default=English"，不含用户输入，不构成开放重定向；4) 无 setcookie/session_start/md5/sha1/rand 等配置型线索，无硬编码凭据；5) 无认证/会话逻辑，无 IDOR/越权面。因此不存在可闭合的 source→sink 利用链，按“宁可漏报不可误报”原则返回空 findings。未闭合线索：该脚本可能被其他文件 include 或部署在更大应用中，其上下文不在 code_pack 内，无法评估；surface_notes 提到的 source 热点（第 3 行）实为注释行，实际输入读取在第 4 行，且已被严格白名单约束。

未覆盖 / 证据缺口：
- code_pack 仅含 049.php，无框架/路由/配置文件/依赖清单，无法评估部署上下文与被 include 时的行为
- 无 sink 热点，未发现任何危险汇点
- 无认证/会话/加密相关代码，配置型风险无可复核项

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
| safety_guard | 安全防护 | 2.3 | 是 |
| surface_mapper | 攻击面测绘 | 6.84 | 是 |
| deep_finder | LLM 深挖 | 3.45 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 4.56 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
