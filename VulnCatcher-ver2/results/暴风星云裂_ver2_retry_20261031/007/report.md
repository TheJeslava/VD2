# 落日二号乙漏洞挖掘报告 — 20261031-001749-efa40a

- 生成时间：2026-10-30T16:18:10.928090+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\007.zip`
- 输入模式：`zip`
- SHA256：`47dd7bdea9f850e88c4cbae3c23033d77110b56a050bbf68a7168677faa9d18f`
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

本次汇总的 findings 为空：去重后没有任何已定性的漏洞条目，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。覆盖范围仅为 1 个 PHP 文件（007.php，110 行，约 5KB），没有框架、没有路由、endpoints=0，属于单文件脚本。攻击面测绘显示 source 热点在第 7 行附近、sink 热点在第 2 行附近，二者同处一个文件且距离很近，提示缺少中间校验层，注入类（命令注入、SQL 注入、路径穿越、SSRF、XSS）是最高优先级的人工核对方向；但由于没有产出任何 finding，本次无法给出最高危漏洞的定性结论，也不能宣称 POC 齐全。所有结论均为源码层面的攻击面测绘，未做动态验证。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 5770 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 007.php（1-110 行，DVWA 风格单页脚本）。逐条核对攻击面：(1) 第 7-17 行用 mysqli_prepare + bind_param 查询当前用户，无拼接；(2) 第 21-25 行 $_GET['user_id'] 先经 preg_match('/^\d+$/') 白名单校验再 intval，随后第 28-34、45-49、95-98 行全部走预处理语句，未发现 SQL 注入；(3) 第 53-61 行输出均经 htmlspecialchars(ENT_QUOTES,'UTF-8')，无 XSS；(4) 第 92 行 HTTP_X_FORWARDED_FOR 仅作为字符串绑定进 bac_log.ip_address（bind_param "iis"），不参与任何查询拼接、权限判断或跳转，属日志字段污染而非可利用注入，且无读取/回显该字段的汇点，不构成闭合链；(5) 第 75-88 行 SHOW TABLES / CREATE TABLE 为静态 SQL，无外部输入；(6) 全文无 include/readfile/file_get_contents/curl/exec/system/反序列化/模板渲染等 sink，无路径穿越、SSRF、命令注入、反序列化面；(7) 配置类：无 md5/sha1/hash、无 rand/mt_rand/uniqid、无 setcookie/session_set_cookie_params、无 mcrypt/openssl，故 weak_hash/weak_random/insecure_cookie/weak_crypto 均无证据。代码注释（第 19、39、60 行）声称存在 session fixation，但本文件内未见 session_regenerate_id 缺失之外的会话固定利用链，且 $_SESSION['user_id'] 在第 107-109 行由服务端 dvwaCurrentUser() 结果赋值，客户端无法直接控制该值，无法在本文件内闭合会话固定→越权链，故不报告。未发现满足 min_severity=high、min_confidence=0.6 的闭合漏洞，findings 为空。

未覆盖 / 证据缺口：
- 无 php.ini/Web 服务器配置，无法确认危险函数禁用与部署暴露面
- endpoints 为空，无法确认 007.php 实际访问路径与 HTTP 方法
- dvwaCurrentUser() 定义不在 code_pack，无法确认其是否读取客户端可控输入（如 Cookie），若其返回客户端可控值则第 107-109 行会话赋值可能形成会话固定链，需人工补充该函数源码
- 第 92 行 X-Forwarded-For 仅写入日志表，若仓库其他文件存在读取 bac_log.ip_address 并回显/拼接的汇点，可能构成二次注入，但相关文件未送入 code_pack，无法闭合
- 未做动态验证，所有结论为源码层面判断

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
| safety_guard | 安全防护 | 2.56 | 是 |
| surface_mapper | 攻击面测绘 | 7.9 | 是 |
| deep_finder | LLM 深挖 | 5.35 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.79 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
