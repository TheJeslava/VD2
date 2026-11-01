# 落日二号乙漏洞挖掘报告 — 20261031-002147-6356f0

- 生成时间：2026-10-30T16:22:06.742139+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\030.zip`
- 输入模式：`zip`
- SHA256：`48d4b3a99200d915a9607662d8cd6ecde38870f14e54fee1fcb0210945f67000`
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

本次汇总的 findings 为空：type_counts 为空、with_poc=0，没有任何已确认漏洞或 POC 工件。覆盖统计显示仅 1 个 PHP 文件（030.php，约 10 行/222 字节），无框架、无端点/路由声明；surface_notes 明确说明输入只提供了文件清单与统计，未提供任何代码行内容，sink_hot_files 为空，因此无法做污点分析或汇点确认。最高危项无法判定——不是因为确认安全，而是因为缺少源码内容这一关键证据。POC 齐全性：0/0，无 HTTP POC，也无静态证据 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 296 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 030.php（共 10 行，完整展示）。该脚本从 $_GET['page'] 读取 $file（第 4 行），随后做两次 str_replace 过滤：第 7 行移除 http:// 与 https://，第 8 行移除 ../ 与 ..\。但脚本在第 10 行结束，CODE PACK 中不存在任何 include/require、file_get_contents/fopen、echo/print、exec/system、SQL 或其它 sink 调用，也没有任何输出或文件操作语句。因此 source（$_GET['page']）到危险汇点的链路在给定代码内不闭合：既无法确认 LFI/path_traversal，也无法确认反射型 XSS 或命令注入。按零容忍误报原则，不产出 finding。<br><br>值得注意的线索（未闭合，不构成结论）：第 7、8 行的 str_replace 黑名单是典型的“假防护”写法——单次替换可被 ../ 嵌套（如 ....//）或 URL 编码绕过，且未做 realpath/白名单校验；若后续（未提供的）代码存在 include($file) 或 file_get_contents($file)，则极可能构成 LFI/路径穿越。但该后续代码不在 code_pack 内，按契约视为不存在，故不报告。<br><br>未覆盖范围：无配置文件（php.ini/.htaccess）、无路由清单、无依赖清单、无认证/会话文件；weak_hash/weak_random/insecure_cookie/weak_crypto/trust_boundary 等配置型候选因脚本中无 md5/sha1/rand/setcookie/openssl 等调用而无法成立。输入中未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- 030.php 第 10 行之后无任何 sink 调用，source→sink 链不闭合，无法确认 LFI/路径穿越
- 缺少 include/require 或文件读取的实际调用点，黑名单过滤的实际影响无法评估
- 无部署配置、路由与依赖信息，无法评估配置型漏洞与第三方组件风险

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
| safety_guard | 安全防护 | 2.77 | 是 |
| surface_mapper | 攻击面测绘 | 7.22 | 是 |
| deep_finder | LLM 深挖 | 3.63 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.36 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
