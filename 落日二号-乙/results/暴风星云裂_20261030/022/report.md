# 落日二号乙漏洞挖掘报告 — 20261030-224753-e8388b

- 生成时间：2026-10-30T14:48:18.929857+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\022.zip`
- 输入模式：`zip`
- SHA256：`c1663891c5c6246a5a3ae32f77dbdd64dbfc5609548a3320760271ea88e17c1b`
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

本次汇总的 findings 为空：去重后没有任何已确认漏洞，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。覆盖范围仅 1 个 PHP 文件（022.php，69 行），无端点清单、无框架、无隔离文件。攻击面测绘指出 source 热点在 022.php:12、sink 热点在 022.php:1，污点路径极短，理论上最可能对应 command_injection / path_traversal / 代码执行类高危问题，但 code_pack 只提供了文件清单与热点行号，未提供具体代码行内容，无法据此确认任何一条注入链，故不产出 finding。最高危的候选是 022.php 中「请求参数→危险汇点」的直接注入链（优先级 1），其次是文件包含/路径拼接（优先级 2），两者均停留在 llm_inferred 推断级别，需人工打开源码核对。POC 不齐全：0 条 finding 对应 0 条 POC，且不存在可宣称可动态复现的条目。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2141 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 022.php 的第 1-57 行（共 69 行，第 58-69 行未送入）。该文件是 DVWA 风格的密码修改页面：第 7-29 行从 JSON body（php://input）或 $_REQUEST 读取 user_token / password_new / password_conf / Change；第 31-33 行在 $change 为真时调用 checkToken($token, $_SESSION['session_token'], 'index.php') 做 Anti-CSRF 校验；第 36 行比较两次输入；第 38 行对 $pass_new 调用 mysqli_real_escape_string；第 39 行 md5 哈希；第 43 行拼接 UPDATE 语句，第 44 行 mysqli_query 执行。逐条核对：(1) SQL 注入：$pass_new 经 mysqli_real_escape_string 转义且随后被 md5() 变为 32 位十六进制，无法携带引号；$current_user 来自 dvwaCurrentUser()（服务端会话派生，非请求参数），且该函数定义不在 code_pack 内，无法证明其受外部控制，故 UPDATE 拼接链不闭合，不报告。(2) 认证/越权：修改目标由 dvwaCurrentUser() 决定而非客户端传入的 user 参数，不存在 IDOR 证据；checkToken 的实现不在 code_pack 内，无法判断其是否可绕过，按“宁可漏报”原则不报告 auth_bypass。(3) 命令执行/文件包含/路径穿越/SSRF/反序列化/模板注入：第 1-57 行内不存在 exec/system/proc_open、include/require、fopen/file_get_contents（除 php://input 固定字面量）、unserialize、eval、curl 等 sink，无对应链。(4) 配置型候选：md5() 用于口令存储属 weak_hash（CWE-328），但 DVWA 为教学靶场、且该哈希前已做转义，单独作为 CVE 级发现价值不足，且 min_severity=high 下不达交付档位，仅作为线索记录；未发现硬编码凭据、弱随机、setcookie 标志位或信任 X-Forwarded-* 的证据。(5) 第 56-57 行 generateSessionToken() 在 JSON 分支重新生成会话令牌，其实现不在 code_pack 内，无法评估会话固定/令牌强度。未闭合线索：checkToken、dvwaCurrentUser、generateSessionToken 三个函数定义均不在 code_pack；

未覆盖 / 证据缺口：
- 022.php 第 58-69 行未送入 code_pack，无法审计输出回显（潜在 XSS）与页面尾部逻辑
- checkToken() 定义缺失，无法判断 Anti-CSRF 校验是否可绕过（如空 session_token 时比较逻辑失效）
- dvwaCurrentUser() 定义缺失，无法确认 $current_user 是否可能受请求头/参数影响而引入二次注入
- generateSessionToken() 定义缺失，无法评估会话令牌随机性与会话固定风险
- 无部署配置（php.ini、allow_url_include、open_basedir）与路由信息，无法确认 022.php 的对外暴露与认证要求
- md5() 口令哈希属 weak_hash 线索，但未达 high 档位且为教学靶场，未单独立项

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
| safety_guard | 安全防护 | 3.35 | 是 |
| surface_mapper | 攻击面测绘 | 9.49 | 是 |
| deep_finder | LLM 深挖 | 5.87 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 6.37 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
