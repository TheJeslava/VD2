# 落日二号乙漏洞挖掘报告 — 20261030-224712-4b3013

- 生成时间：2026-10-30T14:47:36.193516+00:00
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

本次汇总的 findings 为空：去重后没有任何已确认漏洞条目，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。覆盖统计显示仅 1 个 PHP 文件（017.php，112 行，约 3.2KB），0 个端点、无框架、无隔离项。攻击面测绘给出的 source 热点在第 9 行、sink 热点在第 1 处，提示可能存在“取参即用”的直接污点流，但输入未提供 017.php 的代码片段，无法确认具体变量、调用链与汇点类型，故本轮不产出漏洞结论，最高危项无法判定。POC 不齐全（0/0），且不存在可宣称可动态复现的条目。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2688 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅收到 017.php 的前 74 行（共 112 行，shown_ranges 为 1-74），无端点表、无路由、无部署与 php.ini 信息。已审计部分：xor_this() 为固定密钥 "wachtwoord" 的 XOR 加解密工具函数（第 3-14 行），密钥硬编码于第 16 行；POST 处理块（第 26-50 行）读取 $_POST['message'] 与 $_POST['password']，分别经 base64_decode/xor_this 处理，password 与字面量 "Olifant" 做 == 比较（第 41 行）——这是硬编码口令的登录判断，但属于该演示脚本的设计意图，且无会话建立、无后续授权分支，不构成可申报的认证绕过链；$message 在第 59 行经 htmlentities() 输出，XSS 被中和；$_SERVER['PHP_SELF'] 在第 56 行直接拼入 form action，存在反射型 XSS 的经典面（/017.php/"><script>... 形式），但需要目标服务器接受 PATH_INFO 且未做转义，属中危且依赖部署条件，低于本次 min_severity=high，故不单独立项，仅作线索记录。未闭合线索：(1) 第 75-112 行未送入，无法确认 $encoded 解码结果是否以未转义方式回显（若第 75 行之后直接 echo $encoded，则 direction=decode 分支可构造 XSS，需补充该段源码）；(2) 未见 include/require、文件读写、命令执行、SQL、unserialize、eval、curl/file_get_contents 等 sink，故 RCE/注入/SSRF/反序列化面在本段内不成立；(3) 硬编码 XOR 密钥与硬编码口令 "Olifant" 属配置型弱点，但缺少“密钥用于保护真实敏感数据”的证据，且脚本本身即演示性质，不满足 CVE 级影响；(4) 无 md5/sha1、无 mcrypt/openssl、无 rand/mt_rand、无 setcookie，配置类候选在本段内均未出现。结论：在已提供的 1-74 行内没有可闭合的高危利用链，按“宁可漏报不可误报”原则返回空 findings。

未覆盖 / 证据缺口：
- 017.php 第 75-112 行未包含在 code_pack 中，$encoded 的输出上下文（是否 htmlentities/echo）无法确认，可能隐藏 XSS 或信息泄露
- 无 Web 服务器配置，无法确认 PATH_INFO 是否启用，影响 $_SERVER['PHP_SELF'] 反射型 XSS 的可利用性
- 无 php.ini / allow_url_include / open_basedir 信息，无法评估文件包含类风险
- 无端点清单与认证区域信息，无法判断该脚本是否公网可达或位于认证之后
- 无依赖清单，第三方库风险未评估

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
| safety_guard | 安全防护 | 3.05 | 是 |
| surface_mapper | 攻击面测绘 | 9.63 | 是 |
| deep_finder | LLM 深挖 | 5.1 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.54 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
