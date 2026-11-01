# 落日二号乙漏洞挖掘报告 — 20261030-225113-b2674b

- 生成时间：2026-10-30T14:51:37.456137+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\047.zip`
- 输入模式：`zip`
- SHA256：`3fb7cef196d058e1429319161506d9b7757247c40a8879ee94ca463b3d47eead`
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

本次汇总的 findings 为空：type_counts 为空、with_poc=0，没有可交付的漏洞条目，也没有二次注入链。覆盖统计显示仅 1 个 PHP 文件（047.php，13 行 / 289 字节），端点数为 0，无框架、无依赖清单。surface_notes 明确指出输入只提供了文件清单（路径、行数、大小），未提供任何代码内容，sink_hot_files 为空，因此本次无法对 command_injection / sql_injection / xss / path_traversal / ssrf / xpath_injection / ldap_injection 等任何一类给出存在性判断，也无法确认污点链路。最高危项无法排序——不是“无风险”，而是“无源码证据可评级”。POC 齐全度：0 条 finding、0 条 POC，HTTP POC 与静态 POC 均不存在。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 378 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 047.php（13 行，289 字节），已全量通读。代码逻辑：POST 请求时读取/初始化 $_SESSION['last_session_id']，自增后写入 $cookie_value，并通过 setcookie("dvwaSession", $cookie_value) 下发。该文件不含任何外部可控输入（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER 取值参与拼接），无 include/require/eval/system/exec/shell_exec/passthru/popen/proc_open，无 SQL 拼接（mysql_*/mysqli/PDO），无 file_get_contents/fopen/readfile，无 header 跳转，因此不存在可闭合的 source→sink 污点链，command_injection / sql_injection / ssrf / path_traversal / deserialization / ssti / xxe / xss 等均无证据。配置类候选核查：未出现 md5()/sha1()/crc32()（无 weak_hash）；未出现 mcrypt/openssl_encrypt（无 weak_crypto）；未出现 rand()/mt_rand()/uniqid()（无 weak_random）；setcookie 未设置 HttpOnly/Secure/SameSite，属 DVWA 弱会话练习场景的已知设计，但该 Cookie 值仅为服务端会话内自增整数，攻击者无法通过该文件注入或篡改他人会话，且缺少 session_start() 调用与部署上下文，无法构成可申报 CVE 的 insecure_cookie 利用链，故不单独立项，仅作为线索记录。trust_boundary：未使用 X-Forwarded-For/Referer/User-Agent/Host/REMOTE_ADDR 做鉴权或跳转决策。未发现提示注入诱导文本。未闭合线索：文件缺少 session_start()，$_SESSION 是否可用取决于外部包含或 php.ini session.auto_start，属上下文缺失；该文件是否为完整页面或被裁剪片段无法确认；无端点清单与 Web 配置，无法判断对外可达性。按 min_severity=high、min_confidence=0.6 的策略，无满足条件的发现，返回空数组。

未覆盖 / 证据缺口：
- code_pack 仅含 047.php，无其它文件可审计
- 缺少 session_start() 及部署/php.ini 配置，无法确认 $_SESSION 可用性与文件对外可达性
- 无端点清单、无依赖清单、无版本历史，无法评估第三方组件与路由层风险
- setcookie 缺少 HttpOnly/Secure/SameSite 仅为弱配置线索，未形成可利用链，未立项

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
| safety_guard | 安全防护 | 4.33 | 是 |
| surface_mapper | 攻击面测绘 | 8.38 | 是 |
| deep_finder | LLM 深挖 | 4.37 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 6.4 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
