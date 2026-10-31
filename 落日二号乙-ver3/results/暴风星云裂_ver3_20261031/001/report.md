# 落日二号乙漏洞挖掘报告 — 20261031-005721-494fd4

- 生成时间：2026-10-30T16:57:43.783098+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\001.zip`
- 输入模式：`zip`
- SHA256：`9eef8763d9327d2537ce1467f7f2014999c659dd40d8f76a19ca38fb07bdd6c9`
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

本次汇总的 findings 为空（type_counts 为空，with_poc=0），没有任何已确认漏洞或 POC 交付。覆盖统计显示仅审计了 1 个文件（001.php，PHP，约 20 行/1153 字节），无框架、无端点清单、无 source/sink 热点标注、无被隔离文件。攻击面测绘（surface_notes）明确指出：输入未提供 001.php 的源码内容，因此所有风险点均为基于文件类型与体量的结构性推断，不构成漏洞结论。最高危的潜在面是单文件内的参数处理与危险汇点（文件包含/路径拼接、命令执行、SQL 拼接、输出反射），但均无代码证据支撑。POC 不齐全——实际上本次没有任何 POC，且因缺少源码内容，无法生成可复现 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1277 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 001.php（20 行），实际内容为一段静态 HTML 说明文本：第 3 行初始化 $message，第 5-18 行向未初始化的 $html 追加静态字符串（引用 openapi.yml、DVWA 路径说明与 Swagger/Burp/ZAP/Postman 工具链接），第 20 行结束 PHP 块。文件中不存在任何外部输入读取（无 $_GET/$_POST/$_COOKIE/$_SERVER/$_REQUEST）、无 include/require、无文件读写、无 system/exec/shell_exec/passthru、无 eval、无数据库调用、无 header()/setcookie()、无 md5/sha1/openssl/rand 等加密或随机数调用，也无 echo 输出用户数据。因此 surface_notes 中列出的注入、LFI、命令执行、XSS、弱哈希/弱加密/弱随机/不安全 Cookie/信任边界等攻击面在本文件中均无对应代码，无法构成任何 source→sink 链。唯一可注意的实现瑕疵是第 5 行对未定义变量 $html 使用 .= 追加（PHP 8 会触发 Warning），属代码质量问题，不构成安全漏洞，不申报。未闭合线索：surface_notes 提到的 openapi.yml 与 /vulnerabilities/api/v2/health/* 接口（DVWA API v2）不在 code_pack 内，按零工具契约视为不存在，未审计；若后续能提供这些文件，应重点审计 health 系列接口的参数处理。

未覆盖 / 证据缺口：
- 001.php 全文已读，无任何污点源与危险汇点，无可闭合利用链
- openapi.yml 及 /vulnerabilities/api/v2/health/* 后端实现未在 code_pack 中提供，未审计
- 无路由/端点清单、无框架依赖清单、无部署配置，无法评估第三方组件与运行时配置风险

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
| safety_guard | 安全防护 | 3.05 | 是 |
| surface_mapper | 攻击面测绘 | 7.99 | 是 |
| deep_finder | LLM 深挖 | 3.16 | 是 |
| candidate_screener | 候选筛选 | 2.54 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.12 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
