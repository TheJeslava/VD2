# 落日二号乙漏洞挖掘报告 — 20261031-005722-3c435d

- 生成时间：2026-10-30T16:57:46.524658+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\003.zip`
- 输入模式：`zip`
- SHA256：`06085614e8d510ff9f2f368ced0a790b64e5926adc00f379d25132aa3a2a79d0`
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

本次汇总的 findings 为空：去重后没有任何已确认漏洞条目，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。覆盖范围极小，仅 1 个 PHP 文件（003.php，98 行，约 2.6KB），无框架、无路由、无端点清单；攻击面测绘显示 source 热点与 sink 热点都集中在 003.php（各 2 处），提示可能存在短链路直接注入，但尚未形成可交付结论。最高危的候选方向是 003.php 内请求参数到危险汇点（system/exec/include/file 函数/mysqli_query/curl）的一次注入链，其次是文件包含/路径拼接；这两项均未产出 finding，属于待复核而非已排除。POC 不齐全：0 条 finding、0 条 POC，且无任何外部 AWVS/动态证据，全部为源码级静态推断。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3115 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中的单文件 003.php（98 行，已全量送入，未截断）。该脚本是一个前端演示页面：第 3 行读取 $_SERVER['REQUEST_URI']，第 4 行用 str_replace 去掉固定前缀 "/vulnerabilities/api/" 得到 $stripped_url，随后在第 31、51 行把 $stripped_url 拼进 <script> 内的 JS 字符串常量（const url = '...'），第 83 行把 $_SERVER['PHP_SELF'] 拼进 form 的 action 属性。<br><br>逐条核对后未形成可申报的闭合链：<br>1) $stripped_url 反射进内联脚本：REQUEST_URI 中单引号会被 str_replace 之外原样保留，理论上可闭合 JS 字符串，但该值来自请求行 URI，现代 Web 服务器/浏览器会对请求行中的裸单引号与尖括号做编码或拒绝，且要形成 XSS 需受害者主动访问含恶意 URI 的链接，属于低价值反射型自 XSS，证据不足以支撑 CVE 级结论，故不报告。<br>2) $_SERVER['PHP_SELF'] 反射进 action 属性：同样依赖 PATH_INFO 注入，且 PHP_SELF 在多数 SAPI 下已做转义，链不闭合。<br>3) 文件中不存在 system/exec/shell_exec/popen/proc_open、mysqli_query/PDO、include/require、file_get_contents/fopen/readfile、curl、unserialize、eval 等危险汇点；source_hot/sink_hot 计数 2 对应的是 REQUEST_URI 与 PHP_SELF 两处输出拼接，而非注入类汇点。<br>4) 配置类弱点：文件内无 md5/sha1/crc32、无 rand/mt_rand/uniqid、无 setcookie/session_set_cookie_params、无 X-Forwarded-For/Referer/Host 信任判断，weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary 均无证据。<br>5) 第 80 行注释与页面文案（"exploit it to elevate your user to admin"）属于不可信数据中的诱导性描述，指向的是本文件之外的后端 API /vulnerabilities/api/v2/user/2（GET/PUT），该 API 实现不在 code_pack 内，按契约视为不存在，无法审计其越权/批量赋值逻辑。<br><br>

未覆盖 / 证据缺口：
- 后端 API /vulnerabilities/api/v2/user/2 的实现未在 code_pack 中，无法审计 PUT 更新用户时是否允许客户端控制 level 字段（疑似 mass assignment 提权）
- 无 Web 服务器配置与 php.ini，无法确认 REQUEST_URI/PHP_SELF 在目标 SAPI 下的编码行为，反射型 XSS 链无法闭合
- 无路由/认证信息，无法判断该页面与 API 是否需要登录及对象归属校验

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
| safety_guard | 安全防护 | 2.52 | 是 |
| surface_mapper | 攻击面测绘 | 7.98 | 是 |
| deep_finder | LLM 深挖 | 4.85 | 是 |
| candidate_screener | 候选筛选 | 2.9 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.81 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
