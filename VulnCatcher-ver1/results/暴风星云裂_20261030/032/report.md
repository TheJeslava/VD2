# 落日二号乙漏洞挖掘报告 — 20261030-224909-2f0886

- 生成时间：2026-10-30T14:49:30.470011+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\032.zip`
- 输入模式：`zip`
- SHA256：`00f20c6c4951b7689cab1e0be3d0e1d93bb7cb42b3399af954133774b6e161fd`
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

本次输入仅包含一个 PHP 文件 032.php 的文件清单与语言统计（1 个文件、24 行、约 4.2KB），未提供任何源码片段、HTTP 端点清单或 source/sink 热点标注，因此 findings 为空、with_poc=0，没有任何可交付的漏洞结论或 POC。最高危的候选方向是 032.php 作为唯一可能的 HTTP 入口载体，其请求参数处理与输出汇聚点（注入/XSS/路径穿越/文件包含/SSRF/命令执行）以及配置类问题（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary），但全部为基于文件形态的 llm_inferred 推断，证据等级不足以形成 finding。POC 不齐全：既无 HTTP POC，也无静态证据 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 4350 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单个 PHP 文件 032.php（24 行），已逐行审计全部内容。该文件仅做一件事：通过 heredoc 向 $page['body'] 追加一段前端 JavaScript（blueimp JavaScript-MD5 库、rot13 函数、generate_token 函数），随后结束 PHP 标签。文件中不存在任何 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER 等外部输入读取，不存在 include/require、文件读写、SQL 调用、system/exec/shell_exec/passthru、curl/file_get_contents、反序列化、模板渲染或 echo 输出污点；也没有 setcookie/session_set_cookie_params、加密/哈希/随机数生成等配置型证据。generate_token() 在客户端用 md5(rot13(phrase)) 生成 token 属于纯前端逻辑，不构成服务端漏洞，且 rot13+MD5 用于客户端 token 派生不形成可申报 CVE 的服务端利用链。因此无可闭合的 source→sink 链，findings 为空。未闭合线索：$page['body'] 的最终渲染位置与是否被其它文件拼接输出不在 code_pack 内，无法确认是否存在下游 XSS；该文件是否为完整入口、部署路由与认证机制均未知。

未覆盖 / 证据缺口：
- $page['body'] 的后续使用/输出位置不在 code_pack，无法判断是否存在下游反射/存储型 XSS
- 无框架、路由、依赖清单与服务器配置，无法确认该文件的可达性与认证边界
- 无其它文件送入，无法排除被排除的高风险文件
- policy 未给出被抑制候选明细

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
| safety_guard | 安全防护 | 3.65 | 是 |
| surface_mapper | 攻击面测绘 | 8.51 | 是 |
| deep_finder | LLM 深挖 | 3.57 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.65 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
