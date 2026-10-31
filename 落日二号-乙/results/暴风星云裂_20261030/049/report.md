# 落日二号乙漏洞挖掘报告 — 20261030-225128-6d24a0

- 生成时间：2026-10-30T14:51:51.879772+00:00
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

本次汇总的 findings 为空（type_counts 为空，with_poc=0），没有任何已确认漏洞或 POC 交付。覆盖统计显示仅 1 个 PHP 文件（049.php，约 20 行、356 字节），无框架、无路由、无 HTTP 端点清单；攻击面测绘只标出 049.php 第 3 行为 source 热点（存在外部输入读取），sink 热点为空、隔离文件为空，且输入未提供该文件的实际代码内容，因此无法做数据流追踪，所有注入类结论均停留在待确认状态。最高危的待确认方向是 049.php 第 3 行外部输入在无框架过滤层的情况下直接进入拼接/文件/命令/查询/输出（command_injection、sql_injection、xss、path_traversal、ssrf 等），但当前无证据支撑，不能下结论。POC 不齐全：既无 HTTP POC，也无静态证据 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 480 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单文件 049.php（20 行）。逐行审计结果：第 4 行通过 array_key_exists("default", $_GET) 与 !is_null 读取外部输入 $_GET['default']；第 7 行 switch 对该值做严格字符串比较，仅 "French"/"English"/"German"/"Spanish" 四个字面量进入 break 分支，其余全部落入 default 分支执行 header("location: ?default=English") 并 exit。该 header 的 Location 值是硬编码常量，未拼接任何用户输入，因此不构成开放重定向；switch 的松散比较（PHP 8 之前 "0"==0 等）在此处仅影响分支选择，不产生数据外泄或危险汇点。文件中不存在 echo/print 输出、include/require、文件读写、system/exec/shell_exec/popen、SQL 查询、curl/file_get_contents、eval、反序列化、setcookie/session_start、md5/sha1/rand 等任何 sink 或配置型风险证据。surface_notes 中提到的 source 热点（第 3 行）实际为注释行，真实输入读取在第 4 行，且已被白名单 switch 完全约束。因此不存在可闭合的 source→sink 利用链，按“宁可漏报不可误报”原则返回空 findings。未覆盖范围：无 php.ini/Web 服务器配置/composer.json，无法确认部署环境与是否公网暴露；无路由与端点清单，无法确认该脚本可达路径；无历史提交与日志，无法判断是否为遗留调试脚本。上述均为证据缺口，不构成漏洞结论。

未覆盖 / 证据缺口：
- 无 php.ini / Web 服务器配置 / .htaccess / composer.json，运行环境与安全基线未知
- 无 endpoints 与路由信息，无法确认 049.php 的可达路径、请求方法与认证要求
- 无部署方式（容器/裸机、是否公网、是否有 WAF/反向代理）信息
- 无历史提交与日志，无法判断是否为遗留调试脚本或含硬编码凭据
- 配置/实现类风险（weak_crypto / weak_hash / weak_random / insecure_cookie / trust_boundary / hardcoded_secret）在 code_pack 中零证据，属未覆盖而非已排除

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
| safety_guard | 安全防护 | 4.27 | 是 |
| surface_mapper | 攻击面测绘 | 9.48 | 是 |
| deep_finder | LLM 深挖 | 4.41 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.45 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
