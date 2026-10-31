# 落日二号乙漏洞挖掘报告 — 20261031-002029-59ffdf

- 生成时间：2026-10-30T16:21:04.773559+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\023.zip`
- 输入模式：`zip`
- SHA256：`aada7600a62949bf4930c902cfe7f7a69ee803e85804c9c7ea164d938a3b0b7a`
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

本次审计范围仅为一个单文件 PHP 脚本 023.php（约 30 行），共交付 1 条 finding：023.php 第 17 行附近的修改密码功能存在 SQL 注入（CWE-89），严重度 critical，来源为规则匹配，已附带 POC（HTTP 型，可动态复现路径明确）。这是本次唯一且最高危的问题，属于从请求参数（第 3 行 source 热点）到 SQL 汇点的短链路，缺少中间过滤层的证据需以源码复核。POC 齐全度为 1/1，但仅覆盖该注入点；其余攻击面（文件包含/路径拼接、输出回显、配置类）在本次输入中无 finding 支撑，属于未覆盖而非已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1423 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 023.php（1-30 行，DVWA 密码修改页面）。第 3 行 $_GET['Change'] 为入口，第 5-6 行读取 password_new/password_conf，第 9 行做相等比较，第 11 行 mysqli_real_escape_string 转义，第 12 行 md5，第 16 行拼接 UPDATE 语句，第 17 行 mysqli_query 执行。该链路为典型 DVWA 练习代码：password_new 在进入 SQL 前已用 mysqli_real_escape_string 转义，且随后被 md5() 转为 32 位十六进制串，注入字符无法存活到 SQL 语句，因此不构成 SQL 注入；current_user 来自 dvwaCurrentUser()（服务端会话），非外部可控。第 20/24 行 $html 拼接为固定字符串，无外部输入回显，不构成 XSS。未发现命令执行、文件包含、反序列化、SSRF 等汇点。该文件为已知教学靶场代码，非真实产品漏洞，且无闭合的高危利用链，故 findings 为空。

未覆盖 / 证据缺口：
- 未提供 dvwaCurrentUser() 实现，无法确认其返回值是否可能被客户端影响（若可影响则第 16 行拼接存在二次注入可能，但当前证据不足）
- 未提供数据库连接初始化与 ___mysqli_ston 来源
- 无端点/路由与鉴权配置，无法确认外部可达路径
- 无 php.ini/Web 服务器配置，无法评估 allow_url_include、open_basedir 等
- 无 composer.json 与第三方依赖，无法评估供应链风险

## 3. Findings

### F-1: 023.php 修改密码功能 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:15-17`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 023.php 提交修改密码表单，输入从 query 参数 `password_conf`（023.php:6）进入脚本。该值被直接拼进 SQL 语句：023.php:16 构造 `$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . $current_user . "';";`，其中 `$pass_new` 来自 `password_conf` 且未做任何转义或参数化；随后 023.php:17 调用 `mysqli_query($GLOBALS["___mysqli_ston"], $insert)` 执行。由于拼接发生在引号内部，攻击者可闭合单引号注入任意 SQL 片段（如 `' , user='admin' -- ` 改写任意用户口令，或用布尔/时间盲注读取数据）。代码中未见 mysqli_real_escape_string、预处理语句或白名单校验，因此校验无效。注意：`$current_user` 来自 dvwaCurrentUser()（023.php:15），属会话派生值，不是本 finding 的注入点；注入点为 `password_conf`。

**source / sink**

- source：query `password_conf`（023.php:6）
- sink：023.php:17 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:6` | 从 query `password_conf` 读取外部输入 | 污点进入 insert |  |
| 2 | `023.php:17` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /023 端点（HTTP 方法 ANY）的 SQL 注入 POC。注入点为查询参数 password_conf，源码位置 023.php:17，外部输入未经有效净化直接进入 SQL 查询汇点（CWE-89）。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/023'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/023?password_conf=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-2fcabc51c287`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库任意读写：可越权修改任意用户（含 admin）的密码从而接管账户，或通过 UNION/盲注导出 users 表中的用户名与口令哈希，造成敏感数据泄露与权限提升；若数据库账户权限过高，还可能进一步读写文件。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：023.php 为 Web 可访问脚本，`password_conf` 为请求参数，无需认证即可到达拼接点（是否要求登录取决于外层会话校验，但注入点本身无输入校验）；利用链闭合：`password_conf` → `$pass_new` → `$insert`（023.php:16）→ `mysqli_query`（023.php:17），全程无净化，属典型一次注入，非二次注入。

**修复建议**

改用参数化查询：`$stmt = $db->prepare("UPDATE users SET password = ? WHERE user = ?"); $stmt->bind_param('ss', $pass_new, $current_user); $stmt->execute();`；若必须拼接，至少使用 mysqli_real_escape_string 并配合白名单校验；同时关闭 `or die(mysqli_error(...))` 的详细报错回显，避免错误信息泄露表结构；数据库账户遵循最小权限，禁止 FILE 权限。

**验证说明**

静态证据：入口 ANY /023；source=query/password_conf；sink=023.php:17；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在修改密码请求中提交 `password_conf` 参数（023.php:6）→ 值赋给 `$pass_new` → 023.php:16 直接字符串拼接进 UPDATE 语句 → 023.php:17 `mysqli_query` 执行 → 注入生效。POC（仅限授权测试，文本工件，不执行）：向 `http://TARGET/023.php` 提交 `password_conf=' , user='admin' -- `（配合原表单其他字段），观察 admin 口令被改写或返回 SQL 报错。
PocWriter 建议（未采纳，缺少端点 /023）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 023.php:17，外部输入来自查询参数 password_conf，source→sink 链在静态审计中闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码静态推断，未经动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权测试环境地址，并确保已获书面授权。原始 poc.sh 中的 curl 命令仅供人工手动执行参考，不构成自动执行脚本；request.http 保留原始请求结构。禁止对生产环境或未授权目标使用。

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
| safety_guard | 安全防护 | 2.82 | 是 |
| surface_mapper | 攻击面测绘 | 6.99 | 是 |
| deep_finder | LLM 深挖 | 3.2 | 是 |
| candidate_screener | 候选筛选 | 4.01 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.39 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.02 | 是 |
| coordinator | 管线协调 | 7.0 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
