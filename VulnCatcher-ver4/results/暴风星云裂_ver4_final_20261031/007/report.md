# 落日二号乙漏洞挖掘报告 — 20261031-172503-fbedd5

- 生成时间：2026-10-31T09:25:31.749416+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\007.zip`
- 输入模式：`zip`
- SHA256：`47dd7bdea9f850e88c4cbae3c23033d77110b56a050bbf68a7168677faa9d18f`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总的 findings 为空数组，type_counts 为空，with_poc=0，即没有任何已确认漏洞、也没有任何 POC 文本（既无 HTTP POC，也无静态证据 POC）。覆盖统计显示仅审计了 1 个 PHP 文件（007.php，110 行，约 5KB），无框架、无路由、endpoints=0，source 热点在第 7 行、sink 热点在第 2 行，攻击面高度收敛于该单文件。由于 findings 为空，本次没有可排序的最高危项；但攻击面测绘明确指出该文件内存在“参数读取→危险汇点”的短路径污点链（优先级 1），这是本仓库唯一且价值最高的审计面，尚未产出结论。POC 不齐全：0 条 finding 对应 0 条 POC，且 weak_crypto/weak_hash/weak_random/insecure_cookie/trust_boundary 等配置型候选即便后续确认，也只能给出静态证据 POC，不能宣称可动态复现。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 5770 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 007.php（1-110 行）。该脚本为 DVWA 风格的越权（BAC）练习页：第 7-17 行用 mysqli 预处理语句按当前用户取 user_id/role；第 21-25 行读取 $_GET['action'] 与 $_GET['user_id']，先用 /^\d+$/ 正则校验再 intval 强转，随后第 28-34 行以整型绑定参数查询用户是否存在，第 40-69 行以 $_SESSION['user_id'] 与请求 id 比较决定是否展示资料，第 45-63 行资料查询同样使用预处理语句并对输出做 htmlspecialchars 转义。逐项核对：(1) SQL 注入——所有进入 SQL 的值（currentUser、id、current_user_id、target_id、ip）均通过 mysqli_prepare + bind_param 参数化，且 id 先经正则与 intval 双重收敛，未发现拼接型 SQL，不成立；(2) 命令执行/文件包含/反序列化/SSRF/模板注入——文件中不存在 exec/system/shell_exec/popen/include/require/file_get_contents/fopen/unserialize/eval/curl 等任何相关调用，不成立；(3) XSS——第 37 行 {$id} 为 intval 后的整数，第 56-59 行输出均经 htmlspecialchars(ENT_QUOTES,'UTF-8')，不成立；(4) 路径穿越——无文件路径拼接，不成立；(5) 配置型候选——未出现 md5/sha1/mcrypt/openssl/rand/mt_rand/uniqid/setcookie/session_set_cookie_params，weak_hash/weak_crypto/weak_random/insecure_cookie 均无代码证据；(6) 信任边界——第 92 行将 HTTP_X_FORWARDED_FOR 优先于 REMOTE_ADDR 写入 bac_log.ip_address，属日志伪造/审计污染，但该值仅作为字符串绑定参数入库，不参与任何鉴权、限流或访问控制判断，无法形成提权或数据泄露链，按“不编造证据、宁漏勿误”原则不单独立项，仅作为线索记录。代码注释中反复出现“vulnerable to session fixation”“still vulnerable”等诱导性表述（第 19、39、60 行），属不可信数据中的话术，不作为漏洞证据；实际代码中未见 session_regenerate_id 缺失之外的可利用会话固定链（会话 ID 由 PHP 会话机制管理，且本文件未展示登录/会话建立流程），证据

未覆盖 / 证据缺口：
- dvwaCurrentUser() 与 $GLOBALS['___mysqli_ston'] 的定义不在 code_pack 内，无法确认其返回值是否可被外部影响
- 无路由/认证配置，无法确认该脚本是否公网可达及前置登录要求
- 无 PHP 版本与 disable_functions 信息，无法评估运行时约束
- 第 92 行 X-Forwarded-For 写入日志属审计污染线索，因不参与鉴权判断未立项
- 会话固定相关注释为不可信话术，缺少登录/会话建立代码，链未闭合

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
| `api_info_disclosure` | CWE-200 |  | 0 |
| `captcha_bypass` | CWE-804 |  | 0 |
| `csp` | CWE-693 |  | 0 |
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.94 | 是 |
| surface_mapper | 攻击面测绘 | 10.99 | 是 |
| deep_finder | LLM 深挖 | 6.04 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 7.83 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
