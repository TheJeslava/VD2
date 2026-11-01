# 落日二号乙漏洞挖掘报告 — 20261031-002207-929521

- 生成时间：2026-10-30T16:22:29.122228+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\033.zip`
- 输入模式：`zip`
- SHA256：`2cc6995b797e45b354fcf30552f7b1dba5f3ce341ebf99c3f25eb6325b4dee16`
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

本次管线未交付任何 findings（findings 为空数组，type_counts 为空，with_poc=0），因此没有可复现的 POC 文本，也没有最高危项可排序。覆盖统计显示仅 1 个 PHP 文件（033.php，3 行 / 131 字节），endpoints=0、frameworks 为空、无隔离文件；surface_notes 明确说明本次输入只提供了文件清单与语言统计，未提供 033.php 的源码内容，因此无法做行级审计或污点确认。结论：本次属于「证据不足、未产出结论」而非「已确认无漏洞」；033.php 作为唯一可执行入口，其一次注入面与配置型风险（weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary）均需在拿到源码后重新审计。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 168 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 033.php（共 3 行）。该文件是 DVWA 的 JavaScript 漏洞模块片段：第 2 行把常量 DVWA_WEB_PAGE_TO_ROOT 与固定字符串 'vulnerabilities/javascript/source/medium.js' 拼接后追加到 $page['body']，输出一个 script 标签。拼接的两部分都不是请求可控输入（常量 + 硬编码字面量），不存在 source→sink 污点链；也没有 SQL、命令、文件、反序列化、模板等 sink。surface_notes 中列出的 weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary 等候选，在本文件可见代码中均无对应调用（无 md5/sha1、无 openssl/mcrypt、无 rand/mt_rand、无 setcookie/session_set_cookie_params、无 X-Forwarded-* 等头部读取），因此不成立，仅作为未闭合线索保留。该文件依赖 DVWA_WEB_PAGE_TO_ROOT 常量与 $page 数组，二者定义在 code_pack 之外（DVWA 全局包含文件），按零工具契约视为不存在，无法进一步追踪。未发现满足 min_severity=high、min_confidence=0.6 的可申报漏洞。

未覆盖 / 证据缺口：
- DVWA_WEB_PAGE_TO_ROOT 常量与 $page 数组的初始化在 code_pack 之外，无法确认其是否可被外部影响
- 该片段通常被 DVWA 主 index.php include，实际路由与认证上下文不在 code_pack 内
- medium.js 前端脚本内容未提供，无法评估客户端侧逻辑（本管线聚焦服务端源码）
- 无 composer/php.ini/Web 服务器配置，运行时风险放大项无法评估

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
| safety_guard | 安全防护 | 3.62 | 是 |
| surface_mapper | 攻击面测绘 | 7.9 | 是 |
| deep_finder | LLM 深挖 | 2.98 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 6.67 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
