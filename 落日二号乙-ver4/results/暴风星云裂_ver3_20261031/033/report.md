# 落日二号乙漏洞挖掘报告 — 20261031-010238-7759ec

- 生成时间：2026-10-30T17:02:59.206643+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\033.zip`
- 输入模式：`zip`
- SHA256：`2cc6995b797e45b354fcf30552f7b1dba5f3ce341ebf99c3f25eb6325b4dee16`
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

本次汇总的 findings 为空数组，type_counts 为空，with_poc=0，即没有任何已确认漏洞、也没有任何 POC 文本（既无 HTTP POC 也无静态证据 POC）。覆盖统计显示仅 1 个文件（033.php，PHP，3 行 131 字节），endpoints=0，无框架、无隔离文件。攻击面测绘明确指出输入只含文件元数据、不含任何代码片段，因此无法做行级审计，也无法给出 file_path+行号证据。结论：本次没有可交付漏洞，最高危项不存在可排序对象；这不是“已确认安全”，而是“证据不足、未覆盖”。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 168 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含 033.php（3 行，131 字节），内容为 DVWA 的 JavaScript 漏洞模块页面片段：第 2 行将常量 DVWA_WEB_PAGE_TO_ROOT 与固定字符串 'vulnerabilities/javascript/source/medium.js' 拼接后追加到 $page['body']，输出一个 <script src> 标签。该文件不含任何外部输入读取（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER），不含 include/eval/system/exec/proc_open/fopen/unserialize 等危险汇点，也不含哈希、加密、随机数、Cookie 写入或信任边界判断逻辑，因此不存在可闭合的 source→sink 利用链。surface_notes 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 均为“需人工确认”的待审计项，但实际代码中并无对应函数调用，属未覆盖而非存在。DVWA_WEB_PAGE_TO_ROOT 为框架常量，非攻击者可控。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- code_pack 仅提供 033.php 一个文件，DVWA 其余模块（如 javascript/source/medium.js 的实际内容、包含该页面的父级路由与鉴权逻辑）未送入，无法评估该 JS 文件本身或页面渲染上下文中的客户端漏洞
- 无 HTTP 端点清单，无法确认该页面在部署中的可达路径与访问控制
- 无 php.ini / Web 服务器配置，无法判断全局危险配置（如 allow_url_include）

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
| safety_guard | 安全防护 | 2.97 | 是 |
| surface_mapper | 攻击面测绘 | 6.55 | 是 |
| deep_finder | LLM 深挖 | 3.5 | 是 |
| candidate_screener | 候选筛选 | 3.09 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 4.77 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
