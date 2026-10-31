# 落日二号乙漏洞挖掘报告 — 20261031-001725-0e638d

- 生成时间：2026-10-30T16:17:43.134837+00:00
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

本次输入仅包含一个 PHP 文件 001.php（20 行，约 1.1KB），无框架、无 HTTP 端点、无 source/sink 热点标注、无被隔离文件，findings 为空数组，type_counts 为空，with_poc=0。因此本次没有任何已确认漏洞，也没有任何 POC（既无 HTTP POC，也无静态证据 POC）。最高危项无法判定：由于未提供 001.php 的代码片段，无法做行号级定位，攻击面测绘仅给出文件级风险提示（weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary / hardcoded_secret 均属“需人工确认”，不是已检出）。结论：本次交付为空，不代表目标无漏洞，仅代表当前证据不足以支撑任何 finding。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1277 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次输入仅包含单个 PHP 文件 001.php（20 行），内容为静态 HTML 提示页：第 3 行初始化 $message 为空串，第 5-18 行向未初始化的 $html 追加一段固定字符串（提示用户查看 openapi.yml 并用 Swagger UI/Burp/ZAP/Postman 调用 DVWA 的 /vulnerabilities/api/v2/health/* 接口），第 20 行结束 PHP 块。全文没有任何外部输入读取（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER/$_FILES）、没有 include/require、没有 eval/system/exec/shell_exec/passthru、没有数据库调用、没有文件读写、没有 header/setcookie、没有 md5/sha1/rand/openssl 等密码学调用、没有硬编码凭据。因此不存在可闭合的 source→sink 利用链，按“宁可漏报不可误报”原则返回空 findings。注意：surface_notes 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary/hardcoded_secret 均为“需人工确认”的待查项，经逐行核对后确认该文件中均不存在对应调用，属已排除而非未覆盖。文件内文本提到的 openapi.yml 与 /vulnerabilities/api/v2/health/* 端点不在 code_pack 中，按契约视为不存在，未做任何推断。输入中未出现诱导性文本，无 prompt_injection 证据。

未覆盖 / 证据缺口：
- code_pack 仅含 001.php，其引用的 openapi.yml 及 DVWA /vulnerabilities/api/v2/health/* 后端实现未提供，无法评估这些接口是否存在漏洞
- 无路由/部署配置（php.ini、.htaccess、Web 服务器配置）与依赖清单，无法确认 001.php 的实际暴露路径与可达性
- 无版本/提交信息，无法关联已知 CVE

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
| safety_guard | 安全防护 | 2.66 | 是 |
| surface_mapper | 攻击面测绘 | 6.54 | 是 |
| deep_finder | LLM 深挖 | 3.26 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 4.86 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
