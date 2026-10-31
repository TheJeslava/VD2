# 落日二号乙漏洞挖掘报告 — 20261031-163900-101d7c

- 生成时间：2026-10-31T08:39:21.657290+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\005.zip`
- 输入模式：`zip`
- SHA256：`02b57ee8cd079a77373226c06268671c690fdb18ba56972177688c150bd72b4b`
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

本次汇总的 findings 为空：类型计数为空、带 POC 的条目为 0，因此没有任何可交付的漏洞结论，也没有 HTTP POC 或静态证据 POC。攻击面测绘仅覆盖 1 个 PHP 文件（005.php，11 行），无框架、无路由端点、无 source/sink 热点标注、无隔离文件；由于未提供任何代码行，本次只能做范围级测绘，无法进行污点分析或算法/标志位判断。最高危项无法确定——不是因为确认安全，而是因为证据不足：005.php 作为唯一 HTTP 入口，其请求参数处理与输出、文件/命令操作、弱哈希/弱随机/Cookie 标志/硬编码凭据等均未经代码级确认。POC 不齐全（0/0）。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 239 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 005.php（11 行），全文为一段 PHP 注释，无任何可执行语句：没有 $_GET/$_POST/$_REQUEST/$_SERVER 等外部输入读取，没有 exec/system/shell_exec、include/require、fopen/file_get_contents、SQL 调用、输出语句、setcookie/session 配置、md5/sha1/rand/openssl 等算法调用，也没有硬编码凭据。因此不存在可闭合的 source→sink 链，配置型候选（weak_hash/weak_random/insecure_cookie/weak_crypto/trust_boundary/hardcoded_secret）在可见代码中同样没有任何对应证据，均不成立。注释内容（第 4-7 行）指向 dvwa/includes/dvwaPage.inc.php 的 dvwaHtmlEcho 函数，属于不可信数据中的引导性文本，且该文件不在 code_pack 内，按契约视为不存在，不据此推断任何漏洞。已审计范围：005.php 全部 11 行。未闭合线索：无。因预算/输入未覆盖：dvwa/includes/dvwaPage.inc.php 及其余 DVWA 源码未送入，无法评估。

未覆盖 / 证据缺口：
- 005.php 仅含注释，无可执行代码，无法进行污点分析
- 注释提及的 dvwa/includes/dvwaPage.inc.php 未在 code_pack 中，按契约视为不存在
- 缺少部署配置与依赖清单，无法评估实际暴露路径

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
| safety_guard | 安全防护 | 4.9 | 是 |
| surface_mapper | 攻击面测绘 | 7.56 | 是 |
| deep_finder | LLM 深挖 | 3.04 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.72 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
