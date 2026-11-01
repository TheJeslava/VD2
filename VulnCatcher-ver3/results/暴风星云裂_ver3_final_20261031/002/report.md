# 落日二号乙漏洞挖掘报告 — 20261031-013640-2b3a4b

- 生成时间：2026-10-30T17:37:07.161398+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\002.zip`
- 输入模式：`zip`
- SHA256：`e1763d6f3dacb5f1144d8bf313ac2128337f0729a834123f8f766fea9b793fc2`
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

本次汇总的 findings 为空：已去重结果中没有任何已确认漏洞，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。覆盖范围仅 1 个 PHP 文件（002.php，121 行，约 3.1KB），无框架、无路由、无端点清单、无依赖清单。攻击面测绘（surface_notes）基于行号热点推断：source 热点在 002.php:2（疑似超全局变量读取），sink 热点在 002.php:4（疑似文件/命令/输出类危险调用），两者仅隔 2 行，污点路径极短，但 sink 的具体类型（include/require、file_get_contents、unlink、system/exec/eval、echo、mysqli_query）尚未确认，因此无法归类为 path_traversal / command_injection / LFI-RCE / XSS / SQLi 中的任何一类。最高危的候选面是 priority=1 的“请求参数到危险汇点的直接污点链”，但目前只有 llm_inferred 级别的行号推断，没有代码级证据支撑，不能作为漏洞交付。POC 不齐全：0 条 finding 对应 0 条 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3749 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 002.php（1-121 行，完整未截断）。该文件是一个纯前端渲染型 PHP 页面：第 6-7 行的 POST 分支为空，未读取任何请求参数；第 9 行读取 $_SERVER['REQUEST_URI']，第 10 行用 str_replace 去掉固定前缀后于第 47 行拼进 JS 字符串（const url = '...'），这是唯一的外部输入到输出的路径。该拼接点理论上可被 REQUEST_URI 中的单引号/换行打断 JS 字符串，但 REQUEST_URI 由 Web 服务器按请求行原样提供，攻击者需自行构造并访问该 URL，属于自反射（self-XSS 类），无法影响其他用户，且现代浏览器会对请求行中的引号/尖括号做百分号编码，实际可利用性不足，未达到 CVE 门槛，故不单独立项。第 12-119 行其余内容均为静态 HTML/JS 字符串，无 include/require、无文件读写、无 system/exec/eval、无 SQL 连接与查询、无 setcookie/session、无 md5/sha1/rand 等弱算法调用，因此 surface_notes 中列出的 path_traversal、command_injection、LFI/RCE、sql_injection、xss、weak_hash、weak_random、insecure_cookie、weak_crypto、trust_boundary 各攻击面在本文件中均无对应 sink 证据。第 34、81、94 行的 innerHTML 赋值属于客户端 JS 对后端 API 返回数据的渲染，数据源为 /vulnerabilities/api/v2/user/ 接口（不在 code_pack 内，按规则视为不存在），无法在本文件内闭合存储型/反射型 XSS 链。未发现满足 min_confidence 0.6 的可申报漏洞，返回空 findings。

未覆盖 / 证据缺口：
- 002.php 第 47 行拼接的 /vulnerabilities/api/v2/user/ 后端接口实现不在 code_pack 内，无法评估该 API 是否存在越权/信息泄露（页面提示语暗示可返回 password 字段，但无服务端代码佐证）
- 无 php.ini/.htaccess/Web 服务器配置，无法确认 allow_url_include、open_basedir 等利用条件
- 无端点清单与部署路径信息，无法确认 002.php 的实际 URL 与是否位于认证目录之后
- 无 composer 依赖清单，第三方库 CVE 未覆盖
- REQUEST_URI 拼接进 JS 字符串（002.php:9-10 → 47）存在理论上的 JS 上下文注入，但属自反射且受浏览器请求行编码限制，证据不足以立项，留作人工复核线索

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
| safety_guard | 安全防护 | 3.2 | 是 |
| surface_mapper | 攻击面测绘 | 9.05 | 是 |
| deep_finder | LLM 深挖 | 4.35 | 是 |
| candidate_screener | 候选筛选 | 3.14 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 6.46 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
