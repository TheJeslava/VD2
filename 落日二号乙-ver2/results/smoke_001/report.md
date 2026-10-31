# 落日二号乙漏洞挖掘报告 — 20261031-001424-09fa01

- 生成时间：2026-10-30T16:14:47.082684+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\001.zip`
- 输入模式：`zip`
- SHA256：`9eef8763d9327d2537ce1467f7f2014999c659dd40d8f76a19ca38fb07bdd6c9`
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

本次汇总的 findings 为空（type_counts 为空，with_poc=0），没有任何已确认漏洞或 POC 交付。覆盖统计显示仅 1 个 PHP 文件（001.php，约 20 行、1153 字节），无框架、无路由、无已识别 HTTP 端点，且输入未提供该文件源码正文，因此所有注入类与配置类结论都无法落地。最高危项无法判定：surface_notes 给出的 5 个优先排查方向（入口参数与危险汇点、文件包含/路径拼接、命令执行、SQL 拼接、输出反射）均为基于文件规模与语言特征的排查假设，不构成漏洞结论。POC 不齐全——既无 HTTP POC，也无静态证据 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1277 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 001.php（20 行），内容为静态 HTML 说明页：第 3 行初始化 $message，第 5-18 行向 $html 追加一段固定文本（指向 openapi.yml 与 DVWA API 路径的提示），第 20 行结束 PHP 标签。全文未出现任何外部输入读取（$_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER）、未出现 include/require、eval/system/exec/shell_exec/popen/proc_open、数据库调用、文件读写、header/echo 输出污点、md5/sha1/rand/setcookie 等汇点或配置项。$html 在第 5 行以 .= 追加但从未初始化也未输出，属于无害的未定义变量使用（仅可能产生 notice），不构成可利用漏洞。surface_notes 中列出的 LFI/命令注入/SQLi/XSS/弱哈希/弱随机/不安全 Cookie/信任边界/硬编码密钥等方向，在给定源码中均无对应代码证据，全部为基于文件规模的推测，不能作为 finding 交付。未发现满足 min_severity=high、min_confidence=0.6 的闭合 source→sink 链。

未覆盖 / 证据缺口：
- code_pack 仅含 001.php 一个文件，且为静态说明页，无请求处理逻辑；openapi.yml 及提示中提到的 /vulnerabilities/api/v2/health/* 等 API 实现文件未送入 code_pack，视为不存在，无法审计其真实漏洞。
- 无端点清单、无配置文件（php.ini/.htaccess/Web 服务器配置）、无依赖清单，无法评估部署基线与第三方组件。
- surface_notes 中的 medium_review_items（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary/hardcoded_secret）在可见源码中均无对应调用，无法确认也无法排除，属未闭合线索。
- 001.php 第 5 行 $html 未初始化即 .= 追加且从未输出，仅为代码质量问题，不构成安全影响。

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
| safety_guard | 安全防护 | 4.26 | 是 |
| surface_mapper | 攻击面测绘 | 9.24 | 是 |
| deep_finder | LLM 深挖 | 3.84 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.08 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
