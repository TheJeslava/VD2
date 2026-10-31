# 落日二号乙漏洞挖掘报告 — 20261030-225218-f48a18

- 生成时间：2026-10-30T14:52:42.510543+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\057.zip`
- 输入模式：`zip`
- SHA256：`e5aacb8c730b8fc545d6f2efe30ad90b9aa52a5009f9f368746231c2685d2e23`
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

未发现满足 CVE 价值阈值的候选；已审计的范围见覆盖统计。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1455 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 057.php（1-24 行，DVWA 风格 guestbook 留言写入）。数据流：第 3 行 isset($_POST['btnSign']) 触发，第 5-6 行读取 $_POST['mtxMessage'] 与 $_POST['txtName']，第 9-11 行对 message 依次做 addslashes、mysqli_real_escape_string、strip_tags、htmlspecialchars，第 14-15 行对 name 做 str_replace('<script>','') 与 mysqli_real_escape_string，第 18 行拼接 INSERT 语句，第 19 行 mysqli_query 执行。两个参数在拼接前均经过 mysqli_real_escape_string（基于 ___mysqli_ston 连接对象），单引号、反斜杠等 SQL 元字符被转义，字符串上下文内无法闭合引号，SQL 注入链不闭合；name 的 str_replace 黑名单虽弱，但后续 mysqli_real_escape_string 已覆盖 SQL 语义。XSS 方面 message 经 htmlspecialchars、name 经 strip_tags 后写入数据库，若前端原样输出可能仍有存储型 XSS 风险，但读取/渲染点不在 code_pack 内，无法闭合 source→存储→输出汇点三段链，故不报告。配置型面（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）在本文件中均无对应调用（无 md5/sha1/rand/setcookie/HTTP_X_FORWARDED_FOR），不成立。未覆盖范围：无 php.ini/Web 配置、无端点路由、无数据库类型与 PHP 版本、无前端渲染文件，无法确认 057.php 的实际可达路径与输出点；若后续提供留言展示页面，应重新评估存储型 XSS。

未覆盖 / 证据缺口：
- 缺少留言读取/渲染页面，存储型 XSS 输出汇点无法确认
- 无 HTTP 端点与路由信息，057.php 可达性与请求方法未确认
- 无 php.ini/服务器配置，无法评估 mysqli 连接与字符集设置对转义的影响
- 无数据库类型/版本信息

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
| safety_guard | 安全防护 | 4.9 | 是 |
| surface_mapper | 攻击面测绘 | 9.25 | 是 |
| deep_finder | LLM 深挖 | 3.4 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 6.9 | 否 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
