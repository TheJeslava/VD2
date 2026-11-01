# 落日二号乙漏洞挖掘报告 — 20261031-172957-7e451a

- 生成时间：2026-10-31T09:30:20.159459+00:00
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

本次汇总的 findings 为空（type_counts 为空，with_poc=0），因此没有可交付的漏洞结论，也没有任何 POC（既无 HTTP POC，也无静态证据 POC）。覆盖统计显示仅 1 个 PHP 文件（029.php，6 行 / 73 字节），端点数为 0，无框架、无 sink 热点文件，仅第 1 行附近被标记为 source 热点；输入未提供 029.php 源码正文，因此无法确认 source 到 sink 的数据流，最高危项无法判定。攻击面测绘给出的 priority_areas（请求参数入口、文件包含/路径拼接、命令/代码执行、输出反射 XSS、配置类弱哈希/弱加密/弱随机/不安全 Cookie/硬编码密钥）全部属于待确认方向，不构成漏洞结论，已转入 human_review。需特别说明：findings 为空不等于不存在漏洞，而是本次未交付任何候选，且缺少源码正文这一关键证据。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 125 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 029.php（共 6 行，已完整展示，未截断）。该文件仅包含：第 4 行 `$file = $_GET['page'];` 从查询参数 `page` 读取外部输入，随后第 6 行结束 PHP 块，全文没有任何 include/require、文件读写、命令执行、SQL、输出（echo/print）、反序列化或加密/哈希/随机数/会话/Cookie 相关调用。因此 source（`$_GET['page']`）在 CODE PACK 内不存在任何可达 sink，数据流不闭合，无法构造可复现利用链。surface_notes 中列出的 LFI/路径穿越、命令执行、XSS、弱哈希/弱加密/弱随机/不安全 Cookie/信任边界等方向，均因代码正文中缺少对应汇点或配置证据而无法成立；这些只是待确认方向，不是漏洞结论。按“宁可漏报，不可误报”原则，不输出任何 finding。

未覆盖 / 证据缺口：
- 029.php 仅 6 行且无任何危险汇点，`$_GET['page']` 的赋值在文件内未被使用；若真实应用中该变量在未提供的后续代码（如 include 语句）中被消费，则可能构成 LFI，但该部分不在 CODE PACK 内，视为不存在，无法评估。
- 无端点/路由清单，无法确认实际 URL 与 HTTP 方法。
- 无 php.ini / Web 服务器配置，无法判断 allow_url_include、open_basedir 等利用条件。
- 无依赖清单，无法评估第三方组件 CVE。
- 文件仅 73 字节，可能为被截断的样本片段，审计价值受限于可见代码。

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
| safety_guard | 安全防护 | 4.25 | 是 |
| surface_mapper | 攻击面测绘 | 8.38 | 是 |
| deep_finder | LLM 深挖 | 3.58 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 6.06 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
