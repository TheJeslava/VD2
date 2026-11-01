# 落日二号乙漏洞挖掘报告 — 20261031-010228-4e8932

- 生成时间：2026-10-30T17:02:51.456022+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\031.zip`
- 输入模式：`zip`
- SHA256：`b0fc9cc03119c44c0eb5f634603a0bfdc94bdb3472f96b4db80ea87e95d9a867`
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

本次汇总的 findings 为空：管线未交付任何已确认漏洞，type_counts 为空，with_poc=0，因此没有任何 HTTP POC 或静态证据 POC 可供复现。覆盖统计显示仅 1 个 PHP 文件（031.php，3 行 129 字节），endpoints=0、frameworks 为空、quarantined 为空，且输入未提供该文件的源码正文，source/sink 热点均为空。最高危项无法确定——不是因为确认安全，而是因为缺少代码正文与污点对，无法做行号级判断。surface_notes 提出的注入类汇点、动态执行结构、配置/实现类风险（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary/hardcoded_secret）均未被 findings 覆盖，已全部转入 human_review。所有结论证据等级为 llm_inferred，未经任何动态验证。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 166 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 031.php 共 3 行（129 字节），内容为：第 1 行 `<?php`；第 2 行将一段固定字符串（引用 DVWA_WEB_PAGE_TO_ROOT . 'vulnerabilities/javascript/source/high.js'）追加到 $page['body']；第 3 行 `?>`。该片段中不存在任何外部输入读取点（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER 读取），不存在 system/exec/eval/include/file_get_contents/mysql_query/unserialize 等危险汇点，也不存在 md5/sha1/rand/mt_rand/setcookie 等配置型风险调用。$page['body'] 的拼接内容全部为常量与常量 DVWA_WEB_PAGE_TO_ROOT，攻击者无法控制，因此不构成 XSS 或任何注入链。surface_notes 中列出的 weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary / hardcoded_secret 六项 medium_review_items 均基于“单文件 PHP 常见写法”的通用推断，在可见源码中没有任何对应调用，属于未闭合线索而非漏洞，故不产出 finding。该文件看起来是 DVWA 的 javascript 模块片段（high.js 引用），真实攻击面位于未提供的 DVWA 其它文件中，超出本次 code_pack 范围。

未覆盖 / 证据缺口：
- code_pack 仅含 031.php 的 3 行片段，无 DVWA 主框架、无 high.js 内容、无路由与认证代码，无法评估该模块实际攻击面
- 无 php.ini / Web 服务器配置，无法确认 allow_url_include、display_errors 等运行时设置
- 无 composer.json / vendor，无法评估第三方依赖 CVE
- endpoints 为空，无法确认该脚本的请求路径与参数名
- surface_notes 中六项 medium_review_items 在可见源码中均无对应调用，证据不足，未单独立项

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
| surface_mapper | 攻击面测绘 | 8.63 | 是 |
| deep_finder | LLM 深挖 | 3.63 | 是 |
| candidate_screener | 候选筛选 | 3.09 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.1 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
