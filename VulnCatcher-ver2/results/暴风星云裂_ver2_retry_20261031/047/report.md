# 落日二号乙漏洞挖掘报告 — 20261031-002415-991746

- 生成时间：2026-10-30T16:24:36.846591+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\047.zip`
- 输入模式：`zip`
- SHA256：`3fb7cef196d058e1429319161506d9b7757247c40a8879ee94ca463b3d47eead`
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

本次输入仅包含一个 PHP 文件 047.php（13 行、289 字节），findings 为空数组，type_counts 为空，with_poc=0，因此没有任何已确认漏洞，也没有任何 POC（既无 HTTP POC，也无静态证据 POC）。攻击面测绘只在 047.php 第 1 行标出参数读取点（source 热点），sink_hot_files 为空，说明参数到危险汇点的数据流尚未确认；最高危的潜在方向是“参数直达汇点”的单跳注入类问题（命令执行、SQL、文件包含/路径拼接、输出反射），但均停留在待确认攻击面，不能写成结论。由于 findings 为空，本次不存在“最高危已确认漏洞”，也不存在 POC 齐全性判断。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 378 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次输入仅包含单个 PHP 文件 047.php（13 行），已逐行审计。该文件逻辑为：POST 请求时读取/初始化 $_SESSION['last_session_id']，自增后写入 cookie dvwaSession（第 5-11 行）。审计结论：1) 无任何外部请求参数（$_GET/$_POST/$_REQUEST/$_COOKIE/Header）流入 sink，source_hot_files 标记的第 1 行实为 <?php 起始标签，并非参数读取点，surface_notes 中“存在参数入口”的判断与代码不符；2) 无命令执行、SQL、文件包含/路径拼接、反序列化、模板、SSRF、输出反射等危险汇点，不存在可闭合的 source→sink 链；3) 配置型面：setcookie("dvwaSession", $cookie_value) 未设置 HttpOnly/Secure/SameSite，属会话 cookie 加固缺失，但该 cookie 值仅为服务端会话内自增计数器，不承载认证凭据，且无跨用户/跨请求可利用链，未达 high 严重度与 CVE 申报门槛，按策略不单独立项；4) 未出现 md5/sha1、rand/mt_rand、硬编码密钥、X-Forwarded-For 信任等线索。综上，无可申报 CVE 的漏洞，返回空 findings。未覆盖范围：无路由/部署配置/依赖清单，无法确认该脚本访问路径与全局过滤；code_pack 之外文件视为不存在。

未覆盖 / 证据缺口：
- endpoints 为空，无法确认 047.php 的访问路径、HTTP 方法与是否需要认证
- 无 php.ini/Web 服务器/容器配置，无法评估 allow_url_include、open_basedir 等运行时条件
- 无框架与依赖清单，无法评估框架层过滤或已知 CVE
- setcookie 缺少 HttpOnly/Secure/SameSite 属加固建议，因 cookie 值非认证凭据且无利用链，未作为 finding 交付

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
| safety_guard | 安全防护 | 3.24 | 是 |
| surface_mapper | 攻击面测绘 | 8.91 | 是 |
| deep_finder | LLM 深挖 | 3.47 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.73 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
