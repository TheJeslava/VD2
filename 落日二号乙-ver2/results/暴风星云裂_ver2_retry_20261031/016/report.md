# 落日二号乙漏洞挖掘报告 — 20261031-001937-15d13f

- 生成时间：2026-10-30T16:19:59.412841+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\016.zip`
- 输入模式：`zip`
- SHA256：`8496ed015983b44430f1b8716ed9b77300dea2ae53954f97621110e329af01e4`
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

本次汇总的 findings 为空：类型计数为空、带 POC 的条目为 0，因此没有任何已交付漏洞，也没有 HTTP POC 或静态 POC 可供复现。攻击面测绘显示仓库仅含 1 个 PHP 文件 016.php（70 行，约 2KB），无框架、无路由、无端点清单，sink_hot_files 标记该文件有 2 处汇点热点，但未给出函数名与行号；source_hot_files 为空，静态污点链未成形。最高危的候选方向是 016.php 内部 2 处未定位的危险汇点（可能是命令执行、文件操作、SQL 或输出回显），其次是单文件脚本常见的路径穿越/本地文件包含面，以及 weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary / hardcoded_secret 等配置实现类问题。上述均为待复核线索，不是已确认漏洞，更未做动态验证。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2390 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计了 code_pack 中唯一文件 016.php（1-70 行，未截断）。该文件是一个演示页面：第 3 行 require("token_library_high.php")，第 7 行调用 create_token() 生成令牌，第 52/62 行用 htmlentities() 输出到 textarea，第 9-68 行内嵌 JS 将用户输入的 token POST 到 source/check_token_high.php。016.php 自身没有任何 $_GET/$_POST/$_REQUEST/$_COOKIE 读取，没有命令执行、SQL、文件读写、include 动态路径、反序列化、模板求值等 sink；两处 sink 热点实为 htmlentities() 输出，已做 HTML 实体编码，不构成 XSS。真正的令牌生成与校验逻辑位于 token_library_high.php 与 source/check_token_high.php，这两个文件不在 code_pack 中，按契约视为不存在，因此无法判断令牌算法（弱随机/弱加密/可伪造/越权提升为管理员）是否成立。页面文案提示的『解密令牌、伪造管理员令牌』属于业务挑战描述，属不可信数据，不作为漏洞证据。未发现 prompt_injection 诱导文本。按 min_severity=high、min_confidence=0.6 的策略，无可闭合的高危链，返回空 findings。

未覆盖 / 证据缺口：
- token_library_high.php（create_token 实现、令牌加密/签名算法、密钥来源）未在 code_pack 中，无法评估弱加密/弱随机/可伪造令牌
- source/check_token_high.php（令牌校验、身份与 level 判定、是否服务端校验签名）未在 code_pack 中，无法评估认证绕过与权限提升
- 无 Web 服务器配置、路由与包含关系，无法确认 016.php 的实际 URL 与是否对外暴露
- 无 PHP 版本与依赖信息，无法评估反序列化/弱哈希等运行时相关问题

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
| safety_guard | 安全防护 | 3.17 | 是 |
| surface_mapper | 攻击面测绘 | 9.28 | 是 |
| deep_finder | LLM 深挖 | 3.62 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.46 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
