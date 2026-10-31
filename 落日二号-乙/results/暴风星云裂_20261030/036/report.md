# 落日二号乙漏洞挖掘报告 — 20261030-224931-2049b3

- 生成时间：2026-10-30T14:49:54.211417+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\036.zip`
- 输入模式：`zip`
- SHA256：`21f0b55e102a19f7e1305cfce872a6ab1e1c931079a8ad1e4b9dbafe94f87b7f`
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

本次汇总的 findings 为空：去重后没有任何已确认漏洞，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。覆盖范围极窄，仅 1 个 PHP 文件（036.php，21 行，约 395 字节），无框架、无路由、无端点清单，languages 仅 php，quarantined 为空。攻击面测绘指出唯一外部输入采集点在 036.php 第 4 行（疑似超全局变量读取），但 sink 热点为空，数据流下游无证据，注入类结论无法落地。最高危的候选是第 4 行输入点可能流入文件类函数（path_traversal/LFI）或直接回显（反射型 XSS），但均属未验证推断，未形成 finding。POC 不齐全：0 条 finding 对应 0 个 POC，且因缺少 sink 证据，当前也无法产出可信 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 524 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 036.php（21 行）。已逐行审计：第 3-4 行读取 $_GET['redirect'] 并用黑名单正则拦截 http(s)://，第 11 行直接拼入 header("location: ...")。发现一条闭合的开放重定向链（协议相对 URL / 其它 scheme 绕过黑名单）。未发现 SQL、命令执行、文件包含、反序列化等汇点（sink 清单为空与源码一致，脚本内无 include/fopen/system/mysqli 等调用）。无认证、会话、加密相关代码，故无 weak_crypto/weak_hash/insecure_cookie 候选。未覆盖范围：无 composer.json、无 Web 服务器配置、无端点清单，无法确认 036.php 的实际 URL 映射、是否需认证及是否对外暴露；CRLF 头注入因依赖运行时 PHP 版本未单独立项。

未覆盖 / 证据缺口：
- 无部署/路由配置，无法确认 036.php 外部可达性与认证要求
- CRLF 响应头注入依赖 PHP 版本对 header() 换行的处理，未在源码中确认
- 无依赖清单，无法评估第三方组件 CVE

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
| safety_guard | 安全防护 | 3.69 | 是 |
| surface_mapper | 攻击面测绘 | 6.78 | 是 |
| deep_finder | LLM 深挖 | 7.9 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 4.78 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
