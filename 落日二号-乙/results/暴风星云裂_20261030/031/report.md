# 落日二号乙漏洞挖掘报告 — 20261030-224908-7e7c77

- 生成时间：2026-10-30T14:49:27.082215+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\031.zip`
- 输入模式：`zip`
- SHA256：`b0fc9cc03119c44c0eb5f634603a0bfdc94bdb3472f96b4db80ea87e95d9a867`
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

本次汇总的 findings 为空：type_counts 为空、with_poc=0，没有任何已确认漏洞或 POC 工件。攻击面测绘显示仓库仅含单文件 PHP 脚本 031.php（3 行、129 字节），无框架、无路由/端点清单、无认证层证据，且管线未提供该文件的实际源码内容，因此无法定位任何变量、行号或危险汇点，也无法产出 HTTP POC 或静态证据 POC。最高危项无法判定——不是因为确认安全，而是因为缺少代码内容导致注入类与配置类判断均无法落地。POC 不齐全（0 条）。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 166 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 031.php 的 3 行内容（第 1-3 行）：第 1 行为 <?php，第 2 行将一段静态字符串（拼接常量 DVWA_WEB_PAGE_TO_ROOT 与固定路径 'vulnerabilities/javascript/source/high.js'）追加到 $page['body']，第 3 行为 ?>。该文件不含任何外部输入读取（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER/$_FILES），不含任何危险汇点（无 SQL 拼接、无 system/exec/shell_exec、无 include/require 动态路径、无 file 系列函数、无反序列化、无模板求值），也不含弱哈希/弱加密/弱随机/setcookie 等配置型证据。第 2 行拼接的字符串全部为常量与字面量，攻击者无法控制，因此不存在 source→sink 链路，无法构成可申报 CVE 的漏洞。surface_notes 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 均为“待人工确认”的假设项，在可见代码中没有任何对应实现，按零容忍误报原则不予报告。未闭合线索：该文件疑似为 DVWA 的片段/包含文件，其实际可达性依赖未提供的父页面与 DVWA_WEB_PAGE_TO_ROOT 常量定义，这些文件不在 code_pack 内，视为不存在。

未覆盖 / 证据缺口：
- code_pack 仅含 031.php 的 3 行，无其它文件；DVWA_WEB_PAGE_TO_ROOT 的定义与包含该片段的父页面未提供，无法评估整体可达性
- 无部署配置（php.ini、Web 服务器规则），无法确认脚本对外暴露方式
- 无依赖清单与版本信息，无法评估第三方组件 CVE
- surface_notes 中列出的配置型风险项在可见代码中无对应实现，无法落地

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
| safety_guard | 安全防护 | 3.37 | 是 |
| surface_mapper | 攻击面测绘 | 6.88 | 是 |
| deep_finder | LLM 深挖 | 3.52 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 4.63 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
