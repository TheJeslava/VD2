# 落日二号乙漏洞挖掘报告 — 20261031-014137-2849d6

- 生成时间：2026-10-30T17:41:55.420096+00:00
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

本次汇总的 findings 为空（type_counts 为空，with_poc=0），没有任何已确认漏洞或 POC 交付。覆盖统计显示仅 1 个 PHP 文件（031.php，3 行 / 129 字节），0 个 HTTP 端点、无框架、无被隔离文件；攻击面测绘明确指出未提供 031.php 的源码内容，因此无法进行任何污点或汇点分析。最高危的候选并非已确认漏洞，而是 031.php 这一唯一入口本身：3 行极小 PHP 文件常见形态为 eval/assert/base64_decode 一句话或 include 包装器，但当前无代码内容佐证，不能下结论。POC 不齐全——本次既无 HTTP POC 也无静态证据 POC，因为连代码正文都缺失。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 166 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 031.php（3 行，129 字节），已逐行审计：第 1 行为 PHP 开标签；第 2 行将常量 DVWA_WEB_PAGE_TO_ROOT 与固定字符串 'vulnerabilities/javascript/source/high.js' 拼接后追加到 $page['body']，输出一个静态 script 标签；第 3 行为闭标签。该文件不含任何超全局变量读取（$_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER）、不含 exec/system/passthru/shell_exec/eval/assert/include/file_get_contents 等危险汇点、不含 md5/sha1/rand/mt_rand/setcookie 等配置型风险调用，也无硬编码密钥。DVWA_WEB_PAGE_TO_ROOT 为常量而非用户输入，不存在污点源，无法构成 source→sink 闭合链。surface_notes 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary/hardcoded_secret 六项 medium_review_items 均属“需人工确认”的假设，代码中无对应证据，按零容忍误报原则不单独立项。输入中未出现诱导性文本，无 prompt_injection 证据。未覆盖范围：无 HTTP 端点表、无框架/路由信息、无 composer 依赖、无 php.ini/部署配置，故无法评估配置型风险与第三方组件 CVE；这些缺口不影响本文件结论。

未覆盖 / 证据缺口：
- 无 HTTP 端点清单与路由绑定方式，无法确认该片段被哪个页面 include 及 $page 变量的完整上下文
- 无 php.ini/Web 服务器配置（allow_url_include、open_basedir 等），无法评估配置型风险
- 无依赖清单，无法评估第三方组件 CVE
- DVWA_WEB_PAGE_TO_ROOT 常量定义文件未在 code_pack 中，无法确认其取值是否可被外部影响

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
| safety_guard | 安全防护 | 2.31 | 是 |
| surface_mapper | 攻击面测绘 | 5.73 | 是 |
| deep_finder | LLM 深挖 | 3.05 | 是 |
| candidate_screener | 候选筛选 | 2.88 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 4.35 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
