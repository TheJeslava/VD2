# 落日二号乙漏洞挖掘报告 — 20261031-014153-51e76b

- 生成时间：2026-10-30T17:42:14.214580+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\033.zip`
- 输入模式：`zip`
- SHA256：`2cc6995b797e45b354fcf30552f7b1dba5f3ce341ebf99c3f25eb6325b4dee16`
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

本次汇总的 findings 为空：type_counts 为空、with_poc=0，没有任何已去重的漏洞条目，也没有二次注入链。覆盖统计显示仓库仅含 1 个 PHP 文件（033.php，3 行 / 131 字节），无框架、无端点清单、无被隔离文件；攻击面测绘（surface_notes）明确说明本次输入未提供 033.php 的源码内容，因此无法给出任何行号级结论。最高危的候选方向是 033.php 的请求参数处理与输出（潜在注入 / XSS / 路径穿越 / 文件包含），其次是配置实现类风险（弱哈希、弱加密、弱随机、Cookie 标志、信任边界），但这些均属待验证方向，不是已确认漏洞。POC 不齐全：0 条 finding 带 POC，既无 HTTP POC 也无静态证据 POC。本次结论是“无交付项”，不等于“无漏洞”。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 168 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 033.php 共 3 行（131 字节），内容为：第 1 行 `<?php`，第 2 行将一段固定字符串（引用 DVWA_WEB_PAGE_TO_ROOT . 'vulnerabilities/javascript/source/medium.js'）追加到 $page['body']，第 3 行 `?>`。该文件不含任何外部输入读取（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER）、无文件操作、无命令执行、无 SQL/模板/反序列化 sink、无输出回显用户数据、无加密/哈希/随机数/会话 Cookie 设置。第 2 行拼接的常量 DVWA_WEB_PAGE_TO_ROOT 与固定相对路径均非攻击者可控，不构成 XSS 或路径穿越。surface_notes 中列出的 weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary 等候选方向在本文件中均无对应代码证据（无 md5/sha1、无 openssl/mcrypt、无 rand/mt_rand/uniqid、无 setcookie/session_set_cookie_params、无 X-Forwarded-For/REMOTE_ADDR 使用），因此不产出 finding。该文件看起来是 DVWA 的 JavaScript 模块页面片段，实际漏洞逻辑位于其引用的 medium.js 及 DVWA 框架文件中，这些文件不在 code_pack 内，按契约视为不存在，未做推断。

未覆盖 / 证据缺口：
- code_pack 仅含 033.php，引用的 vulnerabilities/javascript/source/medium.js 与 DVWA 框架文件未提供，无法审计其客户端逻辑或服务端包含链
- 无路由/端点清单，无法确认该脚本的对外暴露方式与认证前置条件
- 无配置文件（php.ini/.htaccess）与依赖清单，无法评估安全基线与第三方组件
- policy 中 min_severity=low、min_confidence=0.6，本次无候选达到该档位；不存在被抑制的候选

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
| safety_guard | 安全防护 | 2.6 | 是 |
| surface_mapper | 攻击面测绘 | 7.23 | 是 |
| deep_finder | LLM 深挖 | 3.0 | 是 |
| candidate_screener | 候选筛选 | 2.67 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.48 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
