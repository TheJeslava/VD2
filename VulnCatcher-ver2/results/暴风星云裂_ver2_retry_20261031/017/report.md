# 落日二号乙漏洞挖掘报告 — 20261031-001941-6a238f

- 生成时间：2026-10-30T16:20:05.330512+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\017.zip`
- 输入模式：`zip`
- SHA256：`22eb1c366ca6de367dfb32771c8d253b8bddb6e1e510d5d40c62a409823cb0bf`
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

本次汇总的 findings 为空数组，with_poc=0，因此没有任何已确认漏洞，也没有任何 POC（既无 HTTP POC，也无静态证据 POC）。攻击面测绘显示目标为单文件 PHP 脚本 017.php（112 行），source 热点在第 9 行、sink 热点在第 1 行，污点路径极短，理论上最可能承载命令执行/代码执行/文件包含/路径拼接/SQL 注入类高危缺陷；但输入未提供代码正文，无法确认具体函数与变量，故不能据此下结论。最高危的候选方向是 017.php:1 的 sink 与 017.php:9 的 source 直连路径（优先级 1），其次是路径拼接与命令/代码执行汇点。POC 不齐全：0 条 finding、0 条 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2688 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 017.php 的第 1-74 行（共 112 行，后 38 行未送入）。已逐行审计可见部分：入口为 POST 到 017.php 自身（第 26 行 $_SERVER['REQUEST_METHOD']=='POST'），外部输入为 $_POST['message']（第 29 行）与 $_POST['password']（第 39 行）。message 经 xor_this() 与 base64 编解码后存入 $encoded，password 经 base64_decode+xor_this 后仅与硬编码字符串 "Olifant" 做 == 比较（第 41 行），未进入任何命令执行、SQL、文件、反序列化、模板或代码执行汇点。$message 在第 59 行经 htmlentities() 输出，XSS 被中和；第 56 行 $_SERVER['PHP_SELF'] 拼入 form action 属经典反射型 XSS 面，但 PHP_SELF 在多数现代配置下已由 PHP 自身转义且需路径信息注入，证据不足以构成 CVE 级闭合链，故不报告。第 16 行硬编码 XOR 密钥 "wachtwoord" 与第 41 行硬编码口令 "Olifant" 属硬编码凭据/弱加密线索，但该脚本无认证会话、无受保护资源，无法形成实际越权或数据泄露利用链，按规则仅记入线索不单独立 finding。第 71 行之后（75-112 行）为 $encoded 的输出渲染区，未送入，无法确认是否存在未转义输出（潜在 XSS）或其它汇点，属未闭合缺口。surface_notes 中提到的命令执行/SQL/文件包含/反序列化等假设在可见代码中均无对应 sink，属基于文件级热点的推测而非行级证据。未发现满足 min_severity=high 且链闭合的漏洞，返回空 findings。

未覆盖 / 证据缺口：
- 017.php 第 75-112 行未送入 code_pack，$encoded 的输出渲染逻辑无法审计，可能存在未转义输出导致的 XSS
- 无 php.ini/Web 服务器配置，无法判断 allow_url_include、register_globals 等开关
- 无部署与网络暴露信息，无法确认脚本是否公网可达或位于认证之后
- 第 56 行 $_SERVER['PHP_SELF'] 反射面需结合服务器配置与路径信息注入条件进一步确认
- 硬编码密钥 wachtwoord 与口令 Olifant 缺少受保护资源上下文，无法评估实际影响

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
| safety_guard | 安全防护 | 2.6 | 是 |
| surface_mapper | 攻击面测绘 | 10.16 | 是 |
| deep_finder | LLM 深挖 | 5.45 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.93 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
