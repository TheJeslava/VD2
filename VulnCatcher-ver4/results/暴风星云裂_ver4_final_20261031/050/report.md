# 落日二号乙漏洞挖掘报告 — 20261031-173339-ab3238

- 生成时间：2026-10-31T09:33:55.607135+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\050.zip`
- 输入模式：`zip`
- SHA256：`212a5b21c59855e1cfd8402dd8ea642294dd4b21db31a348ca923303ede5c8c3`
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

本次汇总的 findings 为空：去重后没有任何已确认漏洞，type_counts 为空，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。最高危项无法确定，因为唯一可审计文件 050.php 的源码内容未进入上下文，只有元数据（1 个 PHP 文件、5 行、48 字节、0 个端点、无框架、无隔离文件）。攻击面测绘指出该文件极可能是单条语句（include/require/eval/system/md5/setcookie 等），但这是推断而非证据，不能据此认定存在代码执行、文件包含或弱哈希问题。结论：本轮无可交付漏洞，POC 不齐全（0/0），需补充源码后重跑。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 95 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 050.php（5 行），实际内容为 `<?php`、空行、注释 `# No protections, anything goes`、空行、`?>`，没有任何可执行语句、外部输入读取（$_GET/$_POST/$_COOKIE/$_REQUEST）、动态包含、命令执行、SQL 查询、文件操作、反序列化或加密调用。注释文本属于不可信数据，仅记录为“作者声称无防护”的说明，不构成漏洞证据。由于不存在 source→sink 链路，无法闭合任何利用链，按“宁可漏报不可误报”原则返回空结果。未覆盖范围：无部署配置（.htaccess/nginx/php.ini）、无端点清单、无依赖清单，无法判断该文件是否被其他脚本包含或是否存在 register_globals/allow_url_include 等运行时配置风险；这些均超出 code_pack，视为不存在。

未覆盖 / 证据缺口：
- 050.php 无任何可执行逻辑，无污点源与汇点
- 缺少 Web 服务器与 php.ini 配置，无法评估运行时开关
- 缺少调用方/包含关系信息
- 无依赖清单，无法评估第三方组件

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
| safety_guard | 安全防护 | 2.99 | 是 |
| surface_mapper | 攻击面测绘 | 5.28 | 是 |
| deep_finder | LLM 深挖 | 2.79 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.29 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
