# 落日二号乙漏洞挖掘报告 — 20261031-163837-28c5d0

- 生成时间：2026-10-31T08:38:58.351756+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\004.zip`
- 输入模式：`zip`
- SHA256：`b9fab202b9a48529e59fc3b093ab407f0b2c3c52e487f6da9dfafce8e36fbfc5`
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

本次汇总的 findings 为空：type_counts 为空、with_poc=0，没有任何已确认漏洞或 POC 工件。覆盖统计显示仓库仅 1 个 PHP 文件（004.php，17 行 / 292 字节），无框架、无路由、无端点清单，且输入未提供该文件源码内容，因此无法进行行级审计，也无法给出具体变量与行号。最高危项无法判定——不是因为确认无风险，而是因为唯一交付文件的内容未进入上下文。POC 不齐全：既无 HTTP POC，也无静态证据 POC。surface_notes 提出的 weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary / hardcoded_secret 六类候选均停留在元数据推测层面，需读取 004.php 内容后按代码/会话语义复核，不能视为已验证或已排除。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 401 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 004.php 一个文件（17 行），已逐行审计。该文件只做了一处访问控制判断：第 12 行 `if (dvwaCurrentUser() != "admin")`，不满足则第 13-15 行打印 Unauthorised、返回 403 并 exit。文件中不存在任何外部输入接收点（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER 读取），也不存在危险汇点（无 exec/system/passthru/shell_exec、无 SQL 拼接、无 include/require、无 file_get_contents/file_put_contents、无 unserialize、无 eval、无 setcookie/session 配置、无 md5/sha1/rand 等弱算法调用）。因此 source→sink 链无法闭合，不产出 finding。第 2-10 行注释指向 vulnerabilities/authbypass/change_user_details.php，但该文件不在 code_pack 中，按零工具契约视为不存在，不能据此推断漏洞；注释内容属不可信数据，仅作线索记录。dvwaCurrentUser() 的实现未在 code_pack 中提供，无法判断其是否可被伪造（例如是否依赖客户端可控 Cookie/Header），这是唯一未闭合的线索，需在后续阶段获取该函数定义及 change_user_details.php 后再评估 auth_bypass 可能性。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 函数定义未提供，无法判断身份判定是否可被客户端伪造
- 注释引用的 vulnerabilities/authbypass/change_user_details.php 不在 code_pack 中，无法审计
- 缺少 Web 部署配置与端点清单，无法确认 004.php 的实际可达路径与调用方式

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
| safety_guard | 安全防护 | 5.09 | 是 |
| surface_mapper | 攻击面测绘 | 6.43 | 是 |
| deep_finder | LLM 深挖 | 3.84 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.18 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
