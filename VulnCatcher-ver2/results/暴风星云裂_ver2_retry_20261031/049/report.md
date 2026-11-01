# 落日二号乙漏洞挖掘报告 — 20261031-002433-e71fe1

- 生成时间：2026-10-30T16:24:55.924913+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\049.zip`
- 输入模式：`zip`
- SHA256：`275c9aa49fd32c5baf3a69c1b9199d20f6edf4b8d28cdf1a0598ae6adf1e2b16`
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

本次汇总的 findings 为空：去重后没有任何已确认漏洞，with_poc=0，因此不存在 HTTP POC 或静态证据 POC，POC 不齐全（实际为零）。覆盖统计显示仅 1 个 PHP 文件（049.php，20 行、356 字节），无框架、无端点清单、无被隔离文件；surface_notes 只标出 049.php:3 为请求参数读取热点，sink_hot_files 为空，说明管线未识别到明确汇点，数据流走向无法确认。因此本次没有可判定的最高危项，也不能据此宣称该脚本安全：证据稀薄（未提供源码正文），且 sink 为空既可能是无危险汇点，也可能是动态函数调用/eval 等间接汇点未被识别。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 480 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 049.php（共 20 行，完整可见）。该脚本仅在第 4 行通过 array_key_exists("default", $_GET) 读取 $_GET['default']，第 7 行用 switch 对该值做严格白名单匹配（French/English/German/Spanish），未命中时第 15 行执行固定字符串 header("location: ?default=English") 并 exit。全文件不存在 SQL 拼接、命令执行（system/exec/shell_exec/passthru/popen/反引号）、文件包含或文件读写（include/require/fopen/file_get_contents/readfile）、反序列化、eval/动态函数调用、echo/print 输出反射、setcookie/session、md5/sha1/rand 等任何 sink。$_GET['default'] 仅参与 switch 比较，未进入任何危险操作，source→sink 链不闭合。header() 的 Location 值为硬编码常量，不拼接用户输入，不构成开放重定向或响应头注入。因此无可申报 CVE 的发现，返回空数组。

未覆盖 / 证据缺口：
- 无 endpoints 与部署信息，无法确认该脚本的 URL 路径、是否需认证、是否有前置 WAF/重写规则
- 无 php.ini/.htaccess/nginx 配置，无法评估 allow_url_include、display_errors 等运行时条件
- 无依赖清单与版本历史，无法判断是否为已知 CVE 样本或教学代码
- surface_notes 中列出的 weak_hash/weak_random/insecure_cookie/trust_boundary 复核项在源码中均无对应调用，已排除

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
| safety_guard | 安全防护 | 3.71 | 是 |
| surface_mapper | 攻击面测绘 | 8.99 | 是 |
| deep_finder | LLM 深挖 | 3.72 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.67 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
