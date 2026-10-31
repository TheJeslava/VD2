# 落日二号乙漏洞挖掘报告 — 20261030-224646-a289f8

- 生成时间：2026-10-30T14:47:11.933617+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\014.zip`
- 输入模式：`zip`
- SHA256：`d641901c9e40d65807bfa31417d7720c470dd3f58356dd114ccf3915412bbff4`
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

本次汇总的 findings 为空：type_counts 为空、with_poc=0，没有任何已去重的漏洞条目，也没有二次注入链。覆盖统计显示仅 1 个文件（014.php，PHP，75 行），endpoints=0、frameworks=[]、quarantined=[]，即没有 HTTP 端点元数据、没有框架信息、没有被隔离文件。surface_notes 明确说明输入只给了文件清单与热点行号（source 热点 014.php:9、sink 热点 014.php:1），未提供任何源码片段正文，因此所有攻击面（请求参数直入危险汇点、路径拼接/包含、SQL 拼接、回显 XSS）都只是基于文件规模与热点位置的测绘推断，不构成漏洞结论。最高危的候选方向是 014.php:9 参数到 014.php:1 汇点的短路径注入（命令/代码/文件/SQL 类），但当前无代码证据可确认函数与过滤逻辑，故不列为 finding。POC 不齐全：本次 0 条 POC，既无 HTTP POC 也无静态证据 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3053 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 014.php（1-75 行，DVWA 风格的密码修改页面）。该脚本有两个分支：step=1 分支（第 3-43 行）接收 $_POST['password_new']/$_POST['password_conf']，调用 recaptcha_check_answer 校验验证码，通过后把密码值直接回显进隐藏表单（第 32-33 行，{$pass_new}/{$pass_conf} 未做 htmlspecialchars 编码），存在反射型 XSS 的可能；step=2 分支（第 45-73 行）对 $pass_new 先做 mysqli_real_escape_string（第 56 行）再 md5（第 57 行），最后拼进 UPDATE 语句（第 60 行）执行 mysqli_query（第 61 行）。SQL 侧因 mysqli_real_escape_string 转义 + md5 哈希双重处理，注入链不闭合；第 60 行的 dvwaCurrentUser() 来自会话而非请求参数，无法由外部控制。XSS 侧：第 32-33 行确实未编码回显，但触发需要先通过第三方 reCAPTCHA 校验（第 12-23 行），且回显内容为攻击者自己提交的密码值，属于 self-XSS 性质，难以构成窃取他人会话的完整利用链，按 min_severity=high 与零误报原则不单独立项。weak_hash（md5 存密码，第 57 行）属 CWE-328，但为本地账户口令哈希且需已登录会话，未形成外部可利用链，仅作线索记录。未覆盖/未闭合：recaptcha_check_answer 与 dvwaCurrentUser 的实现不在 code_pack 内，无法确认其校验强度与会话来源；无路由/部署信息，无法确认对外 URL 与请求方法；无 php.ini 等配置，无法判断 register_globals/allow_url_include 等影响。

未覆盖 / 证据缺口：
- recaptcha_check_answer 与 dvwaCurrentUser 定义不在 code_pack，无法确认验证码校验是否可绕过、当前用户是否可被请求参数影响
- 无 HTTP 端点/路由元数据，无法确认该脚本对外暴露路径与请求方法
- 无 php.ini/Web 服务器配置，无法评估 register_globals、allow_url_include、display_errors 等对可利用性的影响
- 第 32-33 行未编码回显的 XSS 需通过 reCAPTCHA 且为 self-XSS，未达到 high 档位，未立项
- 第 57 行 md5 口令哈希属 weak_hash 线索，未形成外部可利用链，未立项

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
| safety_guard | 安全防护 | 4.05 | 是 |
| surface_mapper | 攻击面测绘 | 9.57 | 是 |
| deep_finder | LLM 深挖 | 5.13 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 7.13 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
