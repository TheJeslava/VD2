# 落日二号乙漏洞挖掘报告 — 20261031-002151-ae2653

- 生成时间：2026-10-30T16:22:08.847177+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\031.zip`
- 输入模式：`zip`
- SHA256：`b0fc9cc03119c44c0eb5f634603a0bfdc94bdb3472f96b4db80ea87e95d9a867`
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

本次汇总的 findings 为空数组，type_counts 为空，with_poc=0，即没有任何已去重的漏洞条目，也没有任何 POC（既无 HTTP POC，也无静态证据 POC）。覆盖统计显示仅 1 个文件（031.php，PHP，3 行 / 129 字节），endpoints=0，无框架，无隔离项。攻击面测绘明确说明：输入只提供了文件路径、行数与字节数，未提供 031.php 的实际源码内容，因此无法进行行级审计，所有方向（一句话木马/后门、命令执行、文件包含、输出回显、配置类弱算法/硬编码口令）均为待确认而非结论。最高危项无法判定——不是因为确认安全，而是因为缺少源码证据。POC 不齐全（0 条）。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 166 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入一个文件 031.php（3 行，129 字节），已逐行审计。内容为：第 1 行 `<?php`，第 2 行将一段固定字符串（引用 DVWA_WEB_PAGE_TO_ROOT 常量拼接的 high.js 脚本标签）追加到 `$page['body']`，第 3 行 `?>`。该文件不含任何外部输入取值（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER），不含 include/require、system/exec/eval/assert、文件读写、SQL、反序列化、模板渲染或重定向等 sink；唯一输出为常量拼接的静态 HTML 片段，DVWA_WEB_PAGE_TO_ROOT 为服务端常量而非用户可控，无法构成 XSS 或注入链。因此不存在可闭合的 source→sink 利用链，按 min_severity=high 与零误报原则不产出 finding。未闭合线索：该文件疑似 DVWA 漏洞练习平台的页面片段（依赖外部定义的 $page 与 DVWA_WEB_PAGE_TO_ROOT），其真实可达性取决于未提供的包含方与部署配置；若存在包含该片段的入口文件，需另行审计。

未覆盖 / 证据缺口：
- code_pack 仅含 031.php，无包含该片段的入口文件、路由或部署配置，无法确认外部可达性与 $page 的初始化来源
- 无认证/会话/Cookie 配置，insecure_cookie 与 trust_boundary 无法评估
- 无依赖清单与版本历史，无法评估第三方组件 CVE 或判断是否为遗留调试文件
- DVWA_WEB_PAGE_TO_ROOT 常量定义文件未在 code_pack 中，无法确认其是否可被外部影响

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
| safety_guard | 安全防护 | 3.0 | 是 |
| surface_mapper | 攻击面测绘 | 5.33 | 是 |
| deep_finder | LLM 深挖 | 3.44 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.43 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
