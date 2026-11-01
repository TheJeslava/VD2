# 落日二号乙漏洞挖掘报告 — 20261031-011404-a09012

- 生成时间：2026-10-30T17:14:23.211267+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\004.zip`
- 输入模式：`zip`
- SHA256：`b9fab202b9a48529e59fc3b093ab407f0b2c3c52e487f6da9dfafce8e36fbfc5`
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

本次汇总的 findings 为空：type_counts 为空、with_poc=0，没有可交付的漏洞条目，也没有二次注入链。覆盖范围极小：仅 1 个 PHP 文件 004.php（292 字节、17 行），且输入只提供了文件元数据，没有提供任何源码行，因此无法进行行级审计，也无法给出 file+line 证据。最高危项无法判定：既没有已确认漏洞，也没有可排序的候选；surface_notes 只按文件类型和体量做了先验攻击面排序（优先级 1 为请求参数进入 include/exec/SQL 等汇点，优先级 2 为文件包含与路径拼接，优先级 3 为硬编码凭据、弱哈希、弱加密、弱随机和 Cookie 标志位），证据等级为 llm_inferred。POC 不齐全：0 条 POC，既没有 HTTP POC，也没有静态证据 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 401 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单个 17 行 PHP 文件 004.php（DVWA 风格的授权检查片段）。逐行审计结果：第 12 行 `if (dvwaCurrentUser() != "admin")` 是唯一的逻辑分支，第 13-15 行输出 Unauthorised、返回 403 并 exit。该文件内不存在任何外部输入读取（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER）、无文件/命令/SQL/include/反序列化/模板等 sink、无硬编码凭据、无 md5/sha1/rand/mt_rand、无 setcookie/session 配置、无 header 信任判断。因此在本文件范围内不存在可闭合的 source→sink 利用链，按零容忍误报原则返回空 findings。<br><br>未闭合线索（证据不足，不单独立项）：<br>1) 授权逻辑依赖未在 code_pack 中出现的函数 `dvwaCurrentUser()`（第 12 行）。若该函数从 Cookie/会话中取用户身份且可被客户端伪造，则构成 auth_bypass；但函数实现不在 code_pack 内，无法确认其取值来源与校验方式，属于覆盖缺口而非已证实漏洞。<br>2) 第 8 行注释指向 `vulnerabilities/authbypass/change_user_details.php`，该文件未随 code_pack 提供，无法审计其是否存在越权修改用户资料的问题；注释属不可信数据，仅作为线索记录。<br>3) 无 endpoints 清单、无 Web 服务器/php.ini 配置、无部署暴露信息，无法判断该脚本是否公网可达及 register_globals/allow_url_include 等运行时条件。<br>4) 输入信封内未发现诱导性 prompt injection 文本，仅有文件元数据与攻击面测绘说明。

未覆盖 / 证据缺口：
- 函数 dvwaCurrentUser() 的实现未提供，无法判断身份来源是否可被客户端伪造（潜在 auth_bypass 未闭合）
- 注释引用的 vulnerabilities/authbypass/change_user_details.php 未在 code_pack 中，无法审计
- 缺少 Web 服务器与 php.ini 配置，无法确认运行时利用条件
- 缺少端点清单与网络暴露信息，无法确认该脚本是否为公网入口
- 无依赖清单，无法评估第三方组件 CVE

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
| safety_guard | 安全防护 | 2.55 | 是 |
| surface_mapper | 攻击面测绘 | 6.53 | 是 |
| deep_finder | LLM 深挖 | 3.8 | 是 |
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
