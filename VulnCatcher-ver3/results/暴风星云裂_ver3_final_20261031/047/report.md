# 落日二号乙漏洞挖掘报告 — 20261031-014402-f19fd2

- 生成时间：2026-10-30T17:44:23.247692+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\047.zip`
- 输入模式：`zip`
- SHA256：`3fb7cef196d058e1429319161506d9b7757247c40a8879ee94ca463b3d47eead`
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

本次汇总的 findings 为空：类型计数为空、带 POC 的条目为 0，因此没有任何可交付的漏洞条目，也没有 HTTP POC 或静态证据 POC。攻击面测绘显示项目仅含单个 PHP 文件 047.php（13 行、289 字节），无框架、无路由、无端点清单；source_hot_files 标注第 1 行存在外部输入读取点，但 sink_hot_files 为空，即输入到危险汇点的链路未被管线确认。最高危的待确认点是 047.php 第 1 行外部输入是否流向 include/require、文件操作、SQL、命令执行或 echo 输出，目前仅为测绘推断，未形成 finding。POC 不齐全（0 条），且本次未做任何动态验证。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 378 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 047.php（1-13 行，全文未截断）。该脚本仅在 POST 请求时递增 $_SESSION['last_session_id'] 并通过 setcookie("dvwaSession", $cookie_value) 下发一个自增整数 Cookie。逐行核查结论：(1) 无 $_GET/$_POST/$_COOKIE/$_REQUEST 等外部输入读取，第 1 行被标记为 source 热点属于管线模式误判（实际是 $_SERVER['REQUEST_METHOD'] 的服务器端变量，非攻击者可控内容）；(2) 无 include/require、无 file_get_contents/fopen、无 system/exec/shell_exec/passthru、无 mysqli_query/PDO 拼接、无 echo/print 输出、无 unserialize/eval，sink_hot_files 为空与源码事实一致，不存在可闭合的 source→sink 链；(3) 无 md5/sha1/rand 等弱算法调用，无硬编码凭据，无 setcookie 的 HttpOnly/Secure/SameSite 参数——Cookie 缺少安全标志属于配置加固项，但该 Cookie 值仅为自增整数、不承载认证凭据，且无任何代码读取该 Cookie 做鉴权判断，无法构成可申报 CVE 的利用链，故不单独立 finding，仅作为加固线索记录；(4) 会话 ID 自增可预测（weak_random 类线索）同样因缺少消费方（无读取 dvwaSession 的校验逻辑）而无法闭合。未覆盖范围：无 php.ini/Web 服务器配置、无 composer.json、无路由与认证文件，无法确认 047.php 的实际暴露路径与访问控制；若该脚本在真实部署中由其他文件读取 dvwaSession 做会话判定，则需结合那些文件重新评估会话固定/预测风险。按“宁可漏报不可误报”原则，本次输出空 findings。

未覆盖 / 证据缺口：
- 无 Web 服务器/php.ini 配置，无法确认 047.php 是否公网可达及 URL 路径
- 无读取 dvwaSession Cookie 的消费方代码，会话预测/固定风险无法闭合
- 无认证与会话初始化代码（session_start 未在本文件出现），无法评估会话生命周期
- 无依赖清单与 README，运行环境（PHP 版本）未知

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
| safety_guard | 安全防护 | 2.4 | 是 |
| surface_mapper | 攻击面测绘 | 6.92 | 是 |
| deep_finder | LLM 深挖 | 3.78 | 是 |
| candidate_screener | 候选筛选 | 2.81 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 4.41 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
