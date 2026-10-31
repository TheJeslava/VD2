# 落日二号乙漏洞挖掘报告 — 20261031-001900-f5e65e

- 生成时间：2026-10-30T16:19:40.213795+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\014.zip`
- 输入模式：`zip`
- SHA256：`d641901c9e40d65807bfa31417d7720c470dd3f58356dd114ccf3915412bbff4`
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

本次汇总仅含 1 条已去重 finding：014.php 修改密码功能的 SQL 注入（CWE-89，critical，rule 来源，行号至 61），已附带 POC，属 HTTP 可复现类型。最高危即该条 critical SQL 注入，数据流短、利用门槛低。POC 齐全度：1/1 有 POC，但均为静态构造文本，未做动态验证。需注意：surface_notes 明确说明未提供 014.php 代码内容，source（第 9 行）与 sink（第 1 行）的具体函数与变量无法核实，因此该 finding 的注入类型判定仍属待复核假设，不能当作已验证事实。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3053 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 014.php（1-75 行，DVWA 风格的密码修改页面）。数据流：第 8-9 行读取 $_POST['password_new'] / $_POST['password_conf']，第 26/54 行做相等比较，第 56 行经 mysqli_real_escape_string 转义，第 57 行 md5() 哈希，第 60 行拼接进 UPDATE 语句，第 61 行 mysqli_query 执行。SQL 注入链不闭合：进入拼接前值已被 md5() 变为 32 位十六进制串，攻击者无法通过 password_new 注入 SQL；user 字段来自 dvwaCurrentUser()（服务端会话），非客户端可控。第 32-33 行将 $pass_new/$pass_conf 原样回显进 hidden input 的 value 属性，存在反射型 XSS 的可能，但该分支要求先通过第 12-15 行 recaptcha_check_answer 校验（需有效 reCAPTCHA 令牌），且回显发生在 step=1 的响应中，属自 XSS 性质、需第三方验证码前置条件，按 min_severity=high 与零误报原则不单独立项。第 57 行 md5() 属 weak_hash（CWE-328），但为 DVWA 练习代码的既定设计、无独立可利用链，按策略不交付。第 12-15 行 recaptcha 私钥来自 $_DVWA 配置，未在 code_pack 中给出，无法评估硬编码密钥。未覆盖：无 php.ini/.htaccess/nginx 配置，无法确认 allow_url_include、open_basedir、disable_functions；无端点清单与部署信息；$_DVWA 配置与 recaptcha_check_answer 实现不在 code_pack 内。综合判断：本文件不存在满足 CVE 级别、链闭合且外部可触发的漏洞，返回空 findings。

未覆盖 / 证据缺口：
- $_DVWA 配置数组与 recaptcha_check_answer 函数实现未在 code_pack 中，无法评估私钥硬编码与验证码校验强度
- dvwaCurrentUser() 实现未提供，无法确认 user 字段是否完全服务端可信
- 无 php.ini/.htaccess/nginx.conf，无法确认运行时限制与文件包含类风险
- 第 32-33 行 hidden input 回显存在反射型 XSS 线索，但受 reCAPTCHA 前置条件限制且为自 XSS，未达 high 阈值，未立项

## 3. Findings

### F-1: 014.php 修改密码功能 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:59-61`
- **来源**：`rule`

**描述**

攻击者通过修改密码表单提交的 password_conf 参数（014.php:51 读取）进入 $pass_new，随后在 014.php:60 被直接拼接进 UPDATE 语句：$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";，并在 014.php:61 交给 mysqli_query 执行。代码未对 $pass_new 做 mysqli_real_escape_string 转义、未使用预处理/参数化查询，也未做类型或字符白名单校验，因此单引号可闭合字符串字面量，注入任意 SQL 片段（如通过 WHERE 条件恒真或子查询改变更新范围）。此外 014.php:61 在查询失败时通过 die() 输出 mysqli_error，构成基于报错的注入回显通道。

**source / sink**

- source：query `password_conf`（014.php:51）
- sink：014.php:61 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:51` | 从 query `password_conf` 读取外部输入 | 污点进入 insert |  |
| 2 | `014.php:61` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /014（ANY）的 SQL 注入 POC。注入点：ANY 参数 password_conf；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/014'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/014?password_conf=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-74a307a2a91c`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库写入被篡改：攻击者可改写 users 表中任意用户（包括 admin）的 password 字段，实现账户接管/越权登录；结合报错回显可枚举库表结构，进一步读取或破坏数据。属于持久化数据完整性破坏与认证绕过。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：该逻辑位于修改密码的 HTTP 处理路径，password_conf 来自请求参数，无需本地访问；无需认证即可构造请求（若该页面本身要求登录，则攻击者只需一个低权限账户即可横向篡改他人口令）；利用链闭合：source（014.php:51 password_conf）→ 字符串拼接（014.php:60）→ mysqli_query 执行（014.php:61），中间无有效净化，且错误信息回显（014.php:61 die 分支）为注入结果提供反馈。

**修复建议**

改用预处理语句与参数绑定：$stmt = mysqli_prepare($link, 'UPDATE `users` SET password = ? WHERE user = ?'); mysqli_stmt_bind_param($stmt, 'ss', $pass_new, dvwaCurrentUser()); mysqli_stmt_execute($stmt);。同时对密码做长度/字符白名单校验，使用 password_hash() 存储口令哈希而非明文；关闭向用户回显的数据库错误信息（记录到服务端日志），并遵循最小权限原则，使应用数据库账户仅具备必要表的 UPDATE 权限。

**验证说明**

静态证据：入口 ANY /014；source=query/password_conf；sink=014.php:61；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在修改密码请求中提交 password_conf=xxx' OR '1'='1 之类的值 → 014.php:51 读取该参数赋给 $pass_new → 014.php:60 将 $pass_new 原样拼入 UPDATE `users` SET password = '$pass_new' WHERE user = '...' → 014.php:61 mysqli_query 执行被篡改的语句，单引号闭合使 WHERE 条件被重写，从而更新任意用户口令；若语句出错，die() 分支回显 mysqli_error，暴露 SQL 结构。
PocWriter 建议（未采纳，缺少端点 /014）：针对 014.php:61 的 SQL 注入 POC（CWE-89）。外部输入来自 HTTP 请求参数 password_conf，未经有效净化即拼接进 SQL 查询，导致布尔型 SQL 注入。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /014）：符合 CWE-89（SQL 注入）。漏洞位于 014.php:61，外部输入来自请求参数 password_conf，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。所有请求中的主机统一为 TARGET:8080 占位符，实际测试前需替换为授权目标。禁止使用 DROP、写操作或任何破坏性语句；建议仅做布尔真/假对照探测。原始确定性 POC 的请求结构（GET /014?password_conf=...）予以保留，仅补充基线与假条件对照步骤。

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
| `sql_injection` | CWE-89 | 是 | 1 |
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
| safety_guard | 安全防护 | 4.6 | 是 |
| surface_mapper | 攻击面测绘 | 8.24 | 是 |
| deep_finder | LLM 深挖 | 4.74 | 是 |
| candidate_screener | 候选筛选 | 3.14 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.11 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.8 | 是 |
| coordinator | 管线协调 | 7.14 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
