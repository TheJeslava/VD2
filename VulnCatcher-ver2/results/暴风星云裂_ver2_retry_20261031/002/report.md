# 落日二号乙漏洞挖掘报告 — 20261031-001725-8878a2

- 生成时间：2026-10-30T16:17:47.320399+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\002.zip`
- 输入模式：`zip`
- SHA256：`e1763d6f3dacb5f1144d8bf313ac2128337f0729a834123f8f766fea9b793fc2`
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

本次汇总的 findings 为空：去重后没有任何已确认漏洞，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。最高危的候选来自攻击面测绘对 002.php 的推断：该文件同时被标注为 source 热点（2 处）与 sink 热点（4 处），最可能存在请求参数直达命令执行、SQL、文件操作或输出回显的一次注入/执行链；其次是路径拼接导致的文件包含/读取、反射型 XSS，以及配置型风险（硬编码凭据、弱哈希/弱随机/弱加密、Cookie 标志）。但输入未提供 002.php 的任何代码片段、行号、路由或配置，上述全部为基于文件角色的推断，未做动态验证，不能作为已确认结论。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3749 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 002.php（1-121 行，未截断）。该文件是一个纯前端展示型 PHP 页面：第 6-7 行存在空的 POST 分支，不读取任何请求参数；第 9-10 行读取 $_SERVER['REQUEST_URI'] 并做 str_replace 后拼入第 47 行 JS 字符串常量（const url = '...'），这是唯一的外部输入。该值仅作为 fetch 的 URL 前缀使用，未流入任何服务端 sink（无 SQL、无命令执行、无文件读写、无 include、无反序列化、无 echo 直接回显请求参数）。第 12-119 行全部为静态 HTML/JS 字符串拼接，第 34、81、94 行使用 innerHTML 但数据源是后端 API 返回的 JSON（user_json.name、Object.keys(item)、Object.entries(item)），属于客户端渲染逻辑，不在本文件服务端污点链内，且无法从本文件确认 API 端行为，故不构成可闭合的服务端漏洞。配置类检查：无硬编码凭据、无 md5/sha1、无 rand/mt_rand、无 setcookie/session 调用、无 X-Forwarded-* 信任，均未发现。surface_notes 中提到的 getParameterMap/Runtime.exec/new File/putValue/setSecure 等敏感汇点在代码中均未出现。结论：在给定 code_pack 范围内未发现满足 min_severity=high、min_confidence=0.6 的可闭合漏洞，findings 为空。未闭合线索：第 47 行 $stripped_url 拼入 JS 单引号字符串，若 REQUEST_URI 含单引号可造成客户端 JS 字符串逃逸（反射型 XSS 候选），但需确认 Web 服务器对 REQUEST_URI 的规范化/编码行为以及该页面是否被浏览器直接渲染，证据不足，未达 high 且链未闭合，故不报告。

未覆盖 / 证据缺口：
- 第 47 行 $stripped_url 拼入 JS 单引号字符串存在客户端字符串逃逸/XSS 可能，但依赖 REQUEST_URI 原始编码与浏览器解析，证据不足未报告
- 第 34/81/94 行 innerHTML 渲染后端 API 数据，需审计对应 /vulnerabilities/api/v2/user/ 接口实现，该文件不在 code_pack 内
- 无路由/配置/部署信息，无法确认实际可达 URL 与运行环境（display_errors、WAF 等）
- 无 composer.json 等依赖清单，无法评估第三方组件 CVE

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
| safety_guard | 安全防护 | 2.73 | 是 |
| surface_mapper | 攻击面测绘 | 8.83 | 是 |
| deep_finder | LLM 深挖 | 4.27 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 6.0 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
