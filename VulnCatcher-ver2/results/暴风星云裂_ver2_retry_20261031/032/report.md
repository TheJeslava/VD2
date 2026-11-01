# 落日二号乙漏洞挖掘报告 — 20261031-002200-983c60

- 生成时间：2026-10-30T16:22:21.640937+00:00
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

本次汇总未收到任何已去重的 findings（findings 为空数组，type_counts 为空，with_poc=0），因此没有可交付的漏洞结论，也没有任何 POC（既无 HTTP POC，也无静态证据 POC）。覆盖统计显示仅 1 个 PHP 文件（032.php，24 行，约 4.2KB），无框架、无路由、无端点清单，且输入未提供该文件的任何代码片段，因此所有 source/sink 均无法确认。surface_notes 列出的 6 个优先攻击面（参数入口与危险汇点、文件包含/路径拼接、命令/代码执行、SQL 注入、反射型 XSS、配置实现类问题）全部属于基于文件清单的待确认项，不构成漏洞结论。最高危的候选方向是 032.php 整体入口的参数接收与危险汇点（priority 1），但当前无代码证据，无法定级。结论：本轮为“无交付 + 大面积覆盖缺口”，需补充 032.php 源码内容后重新审计。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 4350 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单文件 032.php（24 行），实际内容为一段 HTML/JavaScript 片段：第 2-23 行通过 heredoc 赋值给 $page['body']，其中内嵌 blueimp JavaScript-MD5 库（第 10 行）、rot13 函数（第 12-14 行）、generate_token 函数（第 16-19 行）以及一次 generate_token() 调用（第 21 行）。该脚本没有任何服务端外部输入读取（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER），没有任何危险汇点（无 include/require、eval/assert、system/exec/shell_exec/passthru/popen、file_get_contents/fopen/readfile/unlink、unserialize、mysqli_/PDO 查询、echo/print 输出请求参数），也没有 setcookie/session 配置或硬编码凭据。第 18 行的 md5(rot13(phrase)) 完全在浏览器端执行，用于把页面输入框的值写入 token 输入框，属于客户端演示逻辑，不构成服务端 weak_hash/weak_crypto 漏洞（无口令存储、无服务端校验、无认证语义）。surface_notes 中列出的所有待确认攻击面（文件包含、命令执行、SQL 注入、XSS、弱哈希/弱加密/弱随机/Cookie 标志、信任边界）在可见代码中均无对应实现，因此无可闭合的 source→sink 链，按“宁可漏报不可误报”原则返回空 findings。未覆盖范围：该文件仅 24 行且 truncated=false，已完整可见；但仓库是否存在其它未送入 code_pack 的文件、Web 服务器/php.ini 配置、以及 $page 变量在其它包含文件中的最终输出位置均不可见，无法评估。

未覆盖 / 证据缺口：
- code_pack 仅含 032.php，仓库其它文件（若有）未送入，无法审计
- $page['body'] 的最终渲染/输出位置不在 code_pack 内，无法确认是否存在服务端拼接或转义缺失
- 无部署配置（nginx/apache、php.ini、allow_url_include 等），无法评估运行时风险
- 无端点清单与认证机制说明，无法判断未授权访问或鉴权绕过
- 客户端 md5(rot13(...)) 仅为前端演示逻辑，未形成服务端安全影响，不作为 finding

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
| safety_guard | 安全防护 | 2.92 | 是 |
| surface_mapper | 攻击面测绘 | 8.74 | 是 |
| deep_finder | LLM 深挖 | 3.95 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.8 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
