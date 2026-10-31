# 落日二号乙漏洞挖掘报告 — 20261031-164415-6086b4

- 生成时间：2026-10-31T08:44:32.733102+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\029.zip`
- 输入模式：`zip`
- SHA256：`9e8e31208f33c79ace21df8e9eb6797c2b16fced272a55592f6c0fe21cce86fa`
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

本次汇总的 findings 为空：去重后没有任何已确认漏洞，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。覆盖范围极小：仅 1 个 PHP 文件（029.php，6 行、73 字节），0 个端点、无框架、无路由配置。攻击面测绘把 029.php:1 标为输入源热点，但 sink_hot_files 为空，说明管线未识别到危险汇点；这只能说明未识别，不能说明不存在。最高危项无法确定，因为输入未提供 029.php 的代码内容，无法做污点或配置型判断。POC 不齐全（0 条），且当前证据不足以生成任何 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 125 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 029.php（共 6 行）。第 4 行 `$file = $_GET['page'];` 确实读取外部输入（与 surface_notes 的 source 热点一致），但该文件在第 6 行 `?>` 处结束，`$file` 之后没有任何使用点：没有 include/require、没有 file_get_contents/fopen/readfile、没有 echo/print、没有 header 跳转、没有 SQL/命令/模板调用。因此 source 存在但 sink 缺失，污点链不闭合，无法构造可复现 POC，按零容忍误报原则不产出 finding。该脚本看起来是被截断的最小演示片段（原意可能是 LFI 示例），但 code_pack 之外的内容视为不存在，不能假设存在 include。配置型风险（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）在可见 6 行内均无对应调用（无 md5/sha1、无 rand/mt_rand、无 setcookie/session、无 $_SERVER 头信任），故也不成立。未闭合线索：若完整版本在 `?>` 之前存在 `include($file)` 或 `readfile($file)` 等语句，则构成典型 path_traversal/LFI，需补充完整源码后重新审计。

未覆盖 / 证据缺口：
- 029.php 仅 6 行且无 sink，$file 变量未被使用，污点链不闭合
- 无 Web 服务器配置/路由/认证信息，无法确认 029.php 是否对外暴露
- 无 composer.json 等依赖清单，无法评估第三方组件
- 若存在被截断的 include/readfile 等语句，需补充完整源码

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
| safety_guard | 安全防护 | 2.89 | 是 |
| surface_mapper | 攻击面测绘 | 6.38 | 是 |
| deep_finder | LLM 深挖 | 3.16 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.2 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
