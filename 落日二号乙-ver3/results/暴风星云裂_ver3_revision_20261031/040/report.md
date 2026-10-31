# 落日二号乙漏洞挖掘报告 — 20261031-012059-fe3884

- 生成时间：2026-10-30T17:21:21.689914+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\040.zip`
- 输入模式：`zip`
- SHA256：`a7a3a902cbf51a117eedf45420f67900d6bd15338d9838b48c773e4175ce8254`
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

本次汇总的 findings 为空：去重后没有任何已确认漏洞，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。覆盖范围仅为单个 PHP 文件 040.php（53 行，约 1.4KB），无框架、无路由、endpoints=0。攻击面测绘把 040.php 标为 sink 热点（计数 1），但未给出具体行号与函数名，source_hot_files 为空，属于“输入未被规则识别”的典型漏报信号，因此本次不能得出“无漏洞”结论，只能说明当前档位下未交付任何条目。最高危的潜在面是 040.php 内的危险函数汇点（命令执行 > 文件包含/路径穿越 > SQL/XPath/LDAP 注入 > XSS > SSRF），但均未取得代码级证据，需人工通读全文确认。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1627 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 040.php 的 1-46 行（共 53 行，尾部 47-53 行未送入）。该文件是 DVWA 的 SQL 注入练习页面（sqli 模块），核心逻辑为：第 3 行检查 $_SESSION['id'] 是否存在，第 5 行 $id = $_SESSION['id']，第 10 行（MySQL 分支）与第 28 行（SQLite 分支）将 $id 直接拼接进 SQL 语句，第 11 行 mysqli_query、第 31 行 SQLite query 执行。从根因看，$id 来自服务端会话而非请求参数，本文件内不存在 $_GET/$_POST/$_REQUEST/$_COOKIE 等外部输入写入 $_SESSION['id'] 的代码；会话写入点位于 code_pack 之外的登录/设置页面（DVWA 中通常由 index.php 的 login 或 security.php 写入），按零工具契约该文件视为不存在，无法确认外部可控性。因此 source→sink 链在本 code_pack 内不闭合，按『宁可漏报不可误报』原则不申报 sql_injection。第 20/44 行 $html 拼接 $id 与数据库字段，属于反射到页面的输出，但同样受限于 $id 来源不可控且未见输出编码缺失的完整外部链，不单独申报 xss。第 33 行将 $e->getMessage() 直接 echo，属异常信息泄露，但触发需先造成 SQL 错误，且信息价值有限，不达 CVE 级别。配置类线索：本段未见 md5/sha1、mcrypt/openssl_encrypt、rand/mt_rand、setcookie/session_set_cookie_params、HTTP_X_FORWARDED_FOR 等调用，surface_notes 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 在本可见范围内均无证据。未发现 prompt_injection 文本。

未覆盖 / 证据缺口：
- 040.php 第 47-53 行未包含在 code_pack 中，无法审计（可能含 SQLite 分支收尾与 HTML 输出）
- $_SESSION['id'] 的写入点不在 code_pack 内，无法确认是否可由外部请求参数控制，这是 SQL 注入链闭合的关键缺口
- 无 endpoints 清单，无法确认该页面的实际路由、请求方法与是否需要认证
- 无 php.ini / Web 服务器配置，无法评估错误显示、magic_quotes 等运行时条件
- surface_notes 提到的配置类审查项（弱哈希/弱加密/弱随机/Cookie 标志/信任边界）在本可见代码段内均无对应调用，未形成 finding

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
| safety_guard | 安全防护 | 2.49 | 是 |
| surface_mapper | 攻击面测绘 | 9.75 | 是 |
| deep_finder | LLM 深挖 | 4.61 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.49 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
