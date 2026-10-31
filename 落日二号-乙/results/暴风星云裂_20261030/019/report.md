# 落日二号乙漏洞挖掘报告 — 20261030-224731-13c0a7

- 生成时间：2026-10-30T14:47:52.699731+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\019.zip`
- 输入模式：`zip`
- SHA256：`6025929a102eb86bb4fd115eeca31f75dc4fa121b1ef36f13f537ead06568b83`
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

本次汇总的 findings 为空：type_counts 为空、with_poc=0，没有交付任何漏洞条目，也没有二次注入链。覆盖统计显示仅 1 个 PHP 文件（019.php，22 行、570 字节），endpoints=0、frameworks=[]、quarantined=[]，属于单文件小样本审计。攻击面测绘只标出 019.php 第 2 行一个 source 热点，sink_hot_files 为空，因此没有任何一条从 source 到 sink 的污点链被确认，最高危项无法判定——这属于证据缺口，不能据此认定不存在漏洞。POC 方面：HTTP POC 与静态 POC 均为 0，无任何可复现工件，不能宣称可动态复现。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 704 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 019.php（22 行，DVWA CSP 练习页 high 级别）。第 2 行并非外部输入接收点，而是硬编码 CSP 响应头字符串（script-src 'self'），surface_notes 将其标为 source 热点属于误判。真正的外部输入在第 8-11 行：$_POST['include'] 被直接拼接到 $page['body'] 并最终输出到 HTML 响应，且第 2-4 行设置的 CSP 仅限制 script-src，未限制 HTML 注入本身。但该拼接点属于 DVWA 靶场刻意设计的练习逻辑（页面文案明确要求修改 source/jsonp.php 以执行代码），且 code_pack 中不存在 jsonp.php、high.js 等被引用文件，无法确认 $page['body'] 的最终输出位置与上下文（是否在 HTML 内、是否被转义），也无法确认该脚本是否对外暴露。因此 source→sink 链在 code_pack 内不闭合，按“宁可漏报不可误报”原则不申报 XSS。未发现命令执行、文件包含、SQL 拼接、反序列化、SSRF 等汇点；无 md5/sha1、rand/mt_rand、setcookie/session_start 等配置型线索。

未覆盖 / 证据缺口：
- code_pack 仅含 019.php，被引用的 source/jsonp.php、source/high.js、DVWA_WEB_PAGE_TO_ROOT 相关文件均未提供，无法确认 $page['body'] 的输出上下文与转义情况
- 无路由/部署信息，无法确认 019.php 是否可被远程访问及请求方法
- 第 8-11 行 $_POST['include'] 拼接为潜在反射型 XSS 线索，但缺少最终 echo/print 汇点与输出上下文，链未闭合，未达 min_confidence 0.6 以上
- 无依赖版本与服务器配置，无法评估第三方组件风险

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
| safety_guard | 安全防护 | 3.42 | 是 |
| surface_mapper | 攻击面测绘 | 8.59 | 是 |
| deep_finder | LLM 深挖 | 4.0 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.63 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
