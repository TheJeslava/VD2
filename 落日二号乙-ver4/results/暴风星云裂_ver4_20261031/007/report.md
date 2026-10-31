# 落日二号乙漏洞挖掘报告 — 20261031-163923-b0fa69

- 生成时间：2026-10-31T08:39:49.778594+00:00
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

本次汇总的 findings 为空：已去重结果中没有任何已确认漏洞，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。覆盖统计显示仅 1 个 PHP 文件（007.php，110 行，约 5KB），端点 0、框架 0、隔离文件 0。攻击面测绘基于元数据指出：第 7 行附近存在外部输入读取，第 2 行附近存在危险汇点，两者同处一个 110 行文件，污点路径极短，是注入类（command_injection / sql_injection / path_traversal / ssrf / xss）的最高价值审计点；但输入未提供代码正文，无法确认第 2 行汇点的具体函数与第 7 行 source 的具体变量，故未形成任何漏洞结论。最高危候选是“外部输入到危险汇点的短链路”，当前仅为待确认的攻击面定位，不是已验证漏洞。POC 不齐全：0 条 finding、0 条 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 5770 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 007.php（1-110 行，DVWA 的 BAC 练习页）。逐条核查了 surface_notes 列出的攻击面：<br>1) SQL 注入：第 7/28/45/95 行全部使用 mysqli_prepare + mysqli_stmt_bind_param 参数化，第 75/80/88 行的 SHOW TABLES / CREATE TABLE 为常量字符串，无外部拼接；第 22 行 preg_match('/^\d+$/') 白名单 + 第 25 行 intval 双重收敛，$_GET['user_id'] 无法改变 SQL 语法。<br>2) 命令执行 / 文件包含 / 路径穿越 / SSRF：文件中不存在 exec/system/shell_exec/popen、include/require、fopen/readfile/file_get_contents/curl 等汇点，第 2 行只是 define('DVWA_WEB_PAGE_TO_ROOT')，并非危险汇点；surface_notes 中“第 2 行危险汇点”的元数据判断与实际代码不符。<br>3) XSS：第 37 行回显 {$id} 前已经过第 22 行正则与第 25 行 intval，只能为纯数字；第 56-59 行数据库字段均经 htmlspecialchars(ENT_QUOTES,'UTF-8') 转义，无反射/存储型 XSS 链。<br>4) 越权/IDOR：第 40-43 行以 $_SESSION['user_id'] 与请求 id 比对，仅允许查看自身资料，服务端校验存在；第 107-109 行在会话缺失时用 dvwaCurrentUser() 推导的 current_user_id 初始化会话，属于 DVWA 框架自身的登录态建立，不是攻击者可控的会话固定原语（攻击者无法指定任意 user_id 写入会话）。<br>5) 配置类：无 md5/sha1、无 mcrypt/openssl、无 rand/mt_rand 生成令牌、无 setcookie/session_set_cookie_params 调用、无硬编码口令或密钥常量，weak_hash/weak_crypto/weak_random/insecure_cookie/hardcoded_secret 均无代码证据。<br>6) 信任边界：第 92 行将 HTTP_X_FORWARDED_FOR 优先于 REMOTE_ADDR 写入 bac_log.ip_address，属日志伪造（可污染审计记录），但该值经第 97 行参数化绑定写入，不构成注入，也不参与任何鉴权/跳转决策，单独不足以申报 CVE，故仅作线索记录，不单独立 finding。<br>未闭合线索：dvwaC

未覆盖 / 证据缺口：
- dvwaCurrentUser() 与 ___mysqli_ston 的定义不在 code_pack 内，会话建立与数据库连接初始化逻辑未覆盖
- 无 php.ini / Web 服务器配置，无法判断 allow_url_include、display_errors 及该页网络暴露与认证前置条件
- 无 composer 依赖清单，第三方库 CVE 未评估
- 第 92 行 X-Forwarded-For 日志伪造仅为低价值线索，未形成可申报链

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
| safety_guard | 安全防护 | 3.96 | 是 |
| surface_mapper | 攻击面测绘 | 9.91 | 是 |
| deep_finder | LLM 深挖 | 6.1 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 6.68 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
