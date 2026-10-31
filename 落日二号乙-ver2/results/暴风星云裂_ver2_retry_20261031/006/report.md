# 落日二号乙漏洞挖掘报告 — 20261031-001747-d6229e

- 生成时间：2026-10-30T16:18:08.095716+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\006.zip`
- 输入模式：`zip`
- SHA256：`aa7e574db02480da83ab6d50b22ba2a55070da964e165c1e99e0e0f5a60fccd3`
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

本次汇总的 findings 为空：type_counts 为空对象，with_poc=0，没有任何已去重的漏洞条目，也没有二次注入链。覆盖统计显示仓库仅 1 个 PHP 文件（006.php，18 行、346 字节），端点数为 0，无框架、无隔离项。攻击面测绘明确指出输入只提供了文件元数据、未提供任何代码行，因此本次无法对 command_injection / sql_injection / xpath_injection / ldap_injection / xss / path_traversal / ssrf 等任何一类给出存在性判断，也无法核对 weak_crypto / weak_hash / weak_random / insecure_cookie / trust_boundary / hardcoded_secret 等配置实现类弱点。最高危结论：当前无任何可交付的高危发现，但这属于证据缺口导致的未判定，而非已排除；006.php 作为唯一入口应作为第一优先人工通读对象。POC 齐全性：无 findings 即无 POC，既无 HTTP POC 也无静态证据 POC，不存在可动态复现的验证材料。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 460 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 006.php 的 18 行内容（1-18 行全部可见，未截断）。逐行审计结果：第 1 行为 PHP 起始标签；第 2-11 行为块注释，其中提到 vulnerabilities/authbypass/get_user_data.php 与 change_user_details.php 两个文件，但这两个文件不在 code_pack 中，按契约视为不存在，注释内容属不可信数据，仅作线索记录；第 13-17 行为访问控制判断：if (dvwaCurrentUser() != "admin") 则打印 Unauthorised、返回 403 并 exit。该文件本身不接收任何外部输入（无 $_GET/$_POST/$_COOKIE/$_REQUEST/$_SERVER 读取），无文件操作、无命令执行、无 SQL 拼接、无 include/require、无反序列化、无输出到 HTML 的反射点，因此在本文件内不存在可闭合的 source→sink 链。dvwaCurrentUser() 的定义不在 code_pack 中，无法判断其是否可被客户端伪造（例如是否直接信任 Cookie 中的用户名），这是唯一未闭合的线索：若该函数从客户端可控 Cookie 读取用户名并与 "admin" 比较，则第 13 行构成认证绕过；但当前无该函数源码，证据不足，按“宁可漏报不可误报”原则不报告。配置型候选（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）在本文件中均无对应实现（无 md5/sha1/rand/mt_rand/setcookie/session_set_cookie_params/X-Forwarded-For 使用），故不产出。surface_notes 中提到的 getParameterMap/Runtime.exec/setSecure 等模式为 Java 语境，与本 PHP 文件无关。未发现提示注入诱导文本。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 的实现不在 code_pack 中，无法确认其取值来源是否客户端可控，认证绕过链无法闭合
- 注释引用的 vulnerabilities/authbypass/get_user_data.php 与 change_user_details.php 未提供源码，无法审计
- 无 Web 服务器/php.ini 部署配置，无法评估 allow_url_include、register_globals 等前置条件
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
| safety_guard | 安全防护 | 3.25 | 是 |
| surface_mapper | 攻击面测绘 | 6.9 | 是 |
| deep_finder | LLM 深挖 | 4.47 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.64 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
