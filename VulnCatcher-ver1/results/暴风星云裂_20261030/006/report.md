# 落日二号乙漏洞挖掘报告 — 20261030-224541-ee7d61

- 生成时间：2026-10-30T14:46:04.231816+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\006.zip`
- 输入模式：`zip`
- SHA256：`aa7e574db02480da83ab6d50b22ba2a55070da964e165c1e99e0e0f5a60fccd3`
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

本次管线未交付任何已确认漏洞：findings 为空数组，type_counts 为空，with_poc=0，因此没有任何 HTTP POC 或静态证据 POC 可交付。覆盖统计显示仅 1 个文件（006.php，PHP，18 行/346 字节），endpoints=0，无框架，quarantined 为空。关键事实是：输入只提供了文件元数据（path/language/lines/size），未提供任何代码行内容，因此无法进行行级审计，也无法给出 file_path+行号级证据；surface_notes 中列出的 eval/include、命令执行、SQL/XPath、输出回显、Cookie 标志位等攻击面全部属于基于文件形态的 llm_inferred 推断，不构成漏洞结论。最高危的待确认项是 006.php 若为 webshell/一句话后门形态（eval/assert/include/命令执行汇点）则对应 RCE，但当前无代码证据，不能写成已发现。POC 不齐全：0 条 finding、0 条 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 460 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 006.php 一个文件，可见范围为 1-18 行，内容为 DVWA 风格的鉴权守卫片段：第 13 行调用 dvwaCurrentUser() 与字符串 "admin" 比较，不相等则 print "Unauthorised"、http_response_code(403) 并 exit。该文件内不存在任何请求参数接收（$_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER）、不存在命令执行、文件包含、SQL/XPath/LDAP 查询、反序列化、模板渲染、输出回显到 HTML 的污点汇点，也不存在 setcookie/session_set_cookie_params、md5/sha1、rand/mt_rand、硬编码密钥等配置型证据。因此在本文件内无法闭合任何 source→sink 利用链，按“宁可漏报不可误报”原则不产出 finding。<br><br>需要说明的关键缺口：第 13 行的 dvwaCurrentUser() 函数定义不在 code_pack 中（按契约视为不存在），无法判断其是否可被伪造（例如是否直接信任 Cookie/Header 中的用户名、是否校验会话）。第 6-9 行注释指向 vulnerabilities/authbypass/get_user_data.php 与 change_user_details.php 两个文件，这两个文件同样不在 code_pack 内，注释属于不可信数据，仅作为线索记录：若后续能取得这两个文件的源码，应重点审计其是否以客户端可控值（Cookie/参数）判定当前用户身份，从而绕过第 13 行的 admin 校验，形成 auth_bypass / IDOR。当前证据不足以支撑该结论。<br><br>另：surface_notes 中列出的 weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary / hardcoded_secret 六项 medium_review_items，经逐行核对 1-18 行均无对应代码，全部不成立。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 的实现不在 code_pack 中，无法判断第 13 行 admin 校验是否可被客户端伪造绕过
- 注释提及的 vulnerabilities/authbypass/get_user_data.php 与 change_user_details.php 未提供源码，auth_bypass/IDOR 线索无法闭合
- 缺少 php.ini / Web 服务器配置，无法确认部署与暴露面
- 无 endpoints 清单，无法确认该脚本的实际路由与访问控制前置条件

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
| safety_guard | 安全防护 | 3.32 | 是 |
| surface_mapper | 攻击面测绘 | 8.83 | 是 |
| deep_finder | LLM 深挖 | 4.51 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 6.31 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
