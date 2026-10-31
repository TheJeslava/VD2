# 落日二号乙漏洞挖掘报告 — 20261030-224711-efd4e8

- 生成时间：2026-10-30T14:47:34.967568+00:00
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

本次管线未产出任何已去重的 findings（findings 为空，type_counts 为空，with_poc=0），因此没有可交付的漏洞条目，也没有任何 POC（既无 HTTP POC，也无静态证据 POC）。攻击面测绘显示范围为单文件 PHP 脚本 016.php（70 行，约 2KB），无框架、无路由、endpoints=0；sink_hot_files 标注 016.php 有 2 处汇点热点，但 source_hot_files 为空，属于“汇点已知、污点来源未建模”的形态，最高优先的人工审计点即这 2 处汇点及其参数来源（可能是 $_GET/$_POST/$_REQUEST/$argv 直接进入 exec/system/popen、文件函数或 SQL 拼接）。由于 findings 为空，本次不存在“最高危已确认漏洞”，只能说最高优先待核项是 016.php 的 2 处汇点。POC 不齐全（0/0）。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2390 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单文件 016.php（70 行），已逐行审计。该文件是一个 CTF/教学风格的 token 挑战页面：第 3 行 require("token_library_high.php") 引入外部库，第 7 行调用 create_token() 生成 token，第 52/62 行通过 htmlentities() 转义后嵌入 HTML 输出，第 9-68 行构造前端 JS 向 source/check_token_high.php 提交 token。文件本身没有任何超全局变量读取（无 $_GET/$_POST/$_REQUEST/$_SERVER/$_COOKIE）、没有 exec/system/popen、没有文件读写、没有 SQL、没有反序列化、没有 include 外部可控路径、没有 md5/sha1/rand/setcookie 等配置型风险调用。唯一的输出点（第 52、62 行）已使用 htmlentities() 转义，且数据源 create_token() 为服务端生成，不构成 XSS。真正的安全逻辑（token 生成算法、签名/加密方式、校验逻辑）位于 token_library_high.php 与 source/check_token_high.php，这两个文件不在 code_pack 内，按规则视为不存在，无法评估 token 可伪造性、弱加密/弱随机、认证绕过等潜在高危问题。因此本文件内不存在可闭合的 source→sink 利用链，不产出 finding。

未覆盖 / 证据缺口：
- token_library_high.php（create_token 实现，可能含弱随机/弱加密/可预测 token）未在 code_pack 中，无法审计
- source/check_token_high.php（token 校验与身份/权限判定逻辑，可能存在认证绕过或权限提升）未在 code_pack 中，无法审计
- 无 composer.json/配置文件/README，无法确认运行环境与部署方式
- endpoints 为空，无法确认实际访问路径与 HTTP 方法
- surface_notes 中提到的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 候选在 016.php 内均无对应调用，无法确认

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
| safety_guard | 安全防护 | 3.9 | 是 |
| surface_mapper | 攻击面测绘 | 9.18 | 是 |
| deep_finder | LLM 深挖 | 3.92 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 6.36 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
