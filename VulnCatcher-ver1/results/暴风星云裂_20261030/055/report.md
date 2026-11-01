# 落日二号乙漏洞挖掘报告 — 20261030-225203-fac1c6

- 生成时间：2026-10-30T14:52:26.702140+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\055.zip`
- 输入模式：`zip`
- SHA256：`3e6e2cddd55f2250b6f1a0ec122303bfa0c923af602a09aecf8d75ca2f525ece`
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

本次汇总的 findings 为空：去重后没有任何已确认漏洞条目，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。攻击面测绘显示，范围是单文件 PHP 脚本 055.php（24 行，约 1.3KB），无框架、无路由、无端点清单；source 热点在第 3 行，sink 热点在同一文件，说明存在一条从请求参数直达敏感操作的短链路，这是本次价值最高的待确认点，但目前尚未形成可交付结论。最高危的候选方向是命令执行/代码执行与文件包含/路径穿越（priority 1-3），其次是反射型 XSS（priority 4），均需人工按源码复核。由于 findings 为空，无法给出 top_findings。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1482 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 055.php（1-24 行，DVWA 风格 guestbook 留言板）。入口为 POST 参数 btnSign/mtxMessage/txtName（第 3、5、6 行），sink 为第 18-19 行 mysqli_query 动态拼接 INSERT 语句。逐跳分析：$message 经 trim→strip_tags→addslashes→mysqli_real_escape_string→htmlspecialchars（第 5、9、10、11 行），$name 经 trim→preg_replace 过滤 script→mysqli_real_escape_string（第 6、14、15 行），两者在进入拼接前均经过 mysqli_real_escape_string 转义，单引号被转义，无法闭合字符串字面量，SQL 注入链不闭合；第 19 行 die() 回显 mysqli_error 属错误信息泄露，但需先触发 SQL 错误，且转义后难以构造，单独不足以构成高危。XSS 方面 $message 经 htmlspecialchars、$name 经 mysqli_real_escape_string 后入库，本文件内无输出回显点（无 echo 输出留言），无法在本 CODE PACK 内闭合存储型 XSS 的读取/渲染汇点，故不报告。未发现命令执行、文件包含、反序列化、SSRF、弱哈希/弱加密/弱随机、Cookie 标志等汇点。medium_review_items 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 在本文件中均无对应代码，属未命中。未闭合线索：若存在其它页面读取 guestbook 表并直接输出 comment/name（本 CODE PACK 未提供），则可能形成二次注入或存储型 XSS，但缺少存储读点与渲染汇点，按规则不报告。

未覆盖 / 证据缺口：
- 无 php.ini/Web 服务器配置，无法确认 allow_url_include、magic_quotes、disable_functions 等开关
- 无其它页面源码，guestbook 表的读取与渲染点不可见，二次注入/存储型 XSS 无法闭合
- 无数据库 schema 与连接初始化代码（$GLOBALS['___mysqli_ston'] 来源不可见）
- 无路由/认证信息，无法确认该脚本部署路径与访问控制

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
| safety_guard | 安全防护 | 3.67 | 是 |
| surface_mapper | 攻击面测绘 | 9.01 | 是 |
| deep_finder | LLM 深挖 | 4.38 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 6.15 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
