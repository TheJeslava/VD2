# 落日二号乙漏洞挖掘报告 — 20261030-224910-0de7f4

- 生成时间：2026-10-30T14:49:29.223464+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\033.zip`
- 输入模式：`zip`
- SHA256：`2cc6995b797e45b354fcf30552f7b1dba5f3ce341ebf99c3f25eb6325b4dee16`
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

本次汇总的 findings 为空：类型计数为空、带 POC 的条目为 0，因此没有任何可交付的漏洞结论，也没有 HTTP POC 或静态证据 POC。覆盖统计显示仓库仅含 1 个 PHP 文件（033.php，3 行 / 131 字节），无框架、无端点清单、无被隔离文件；关键缺口是输入未提供 033.php 的源码内容，无法做行级审计，也无法给出 file+line 证据。最高危项无法判定——不是因为确认安全，而是因为缺少代码内容，注入类（command/sql/xpath/ldap 注入、xss、path_traversal、ssrf）与配置实现类（weak_crypto/weak_hash/weak_random/insecure_cookie/trust_boundary/hardcoded_secret）均处于“证据不足、未交付”状态。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 168 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 033.php 的 3 行内容（第 1-3 行）：第 1 行为 <?php 开标签，第 2 行把一段静态字符串（引用 DVWA_WEB_PAGE_TO_ROOT 常量拼接的 medium.js 脚本标签）追加到 $page['body']，第 3 行为 ?> 闭标签。该文件没有任何外部输入接收点（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER 取值），没有 include/require/eval/system/exec/file_get_contents/unserialize 等危险汇点，也没有哈希、加密、随机数、Cookie 标志位或信任边界判断逻辑。第 2 行拼接的 DVWA_WEB_PAGE_TO_ROOT 是常量而非用户可控数据，且输出目标是页面 body 的静态脚本引用，不构成可利用的注入链。因此不存在满足 min_severity=high、min_confidence=0.6 的闭合 source→sink 链，findings 为空。surface_notes 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 五类 medium_review_items 在可见代码中均无对应实现证据（无 md5/sha1/crypt、无 openssl/mcrypt、无 rand/mt_rand/uniqid、无 setcookie/session_set_cookie_params、无 X-Forwarded-For/Referer 等取值），按“宁可漏报不可误报”原则不单独立项，仅作为未闭合线索保留。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- 033.php 仅 3 行且为片段式代码（依赖未定义的 DVWA_WEB_PAGE_TO_ROOT 常量与 $page 数组），无法确认其所属完整应用的入口、路由与认证形态
- 无 php.ini / Web 服务器配置 / .htaccess / composer.json，无法评估危险函数启用状态与部署方式
- 无端点清单与请求样例，外部可达性无法确认
- 无版本/提交信息，无法关联已知 CVE
- surface_notes 中 weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary 五类候选在可见代码中无实现证据，属证据不足而非确认不存在

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
| safety_guard | 安全防护 | 3.6 | 是 |
| surface_mapper | 攻击面测绘 | 5.74 | 是 |
| deep_finder | LLM 深挖 | 3.86 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.41 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
