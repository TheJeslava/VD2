# 落日二号乙漏洞挖掘报告 — 20261031-172525-9d1559

- 生成时间：2026-10-31T09:26:08.786685+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\010.zip`
- 输入模式：`zip`
- SHA256：`819467f4e89f5ccb8366890305cd0e83be79b38873b4535d43cf0f2c08e7c6c7`
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

本次汇总基于已去重的 2 条 findings，均来自单文件 PHP 项目 010.php（43 行）。最高危为 GEN-7034f0a19983：010.php 第 20 行附近的登录查询 SQL 注入（CWE-89，critical，rule 来源），请求输入与 SQL 汇点同处一个短脚本内、缺少过滤中间层，可利用性高。其次为 SEM-949d40928ae7：010.php 第 16 行附近口令使用 MD5 哈希（按 CWE-328 归为弱哈希，类型标签沿用输入中的 weak_crypto，定级 medium）。两条均标记 has_poc=true，但需区分：SQL 注入为 HTTP 型 POC（可构造请求复现，目标以 TARGET 占位，仅限授权测试）；MD5 弱哈希仅为静态证据 POC，不能宣称可动态复现。本次未发现二次注入三段链证据（无存储写点/读点线索），也未交付配置类与信任边界类结论。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2114 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 010.php（1-43 行，DVWA 风格登录脚本）。第 3 行 $_GET['Login'] 触发登录分支，第 8/13 行读取 username/password，第 9-10、14-15 行经 stripslashes 与 mysqli_real_escape_string 转义后在第 19 行拼接进 SQL，第 20 行 mysqli_query 执行。由于 mysqli_real_escape_string 在已建立连接（$GLOBALS['___mysqli_ston'] 为对象）时对单引号等元字符做了正确转义，且第 16 行对密码做 md5 后仅剩十六进制字符，username 的注入面被转义封堵，未发现可闭合的 SQL 注入链；若连接对象缺失则第 10/15 行会 trigger_error 并置空，也不构成注入。第 28-29 行 $user 与 $avatar 回显到 HTML，但 $user 已经过 mysqli_real_escape_string（不转义 < > 但该脚本无其它可控注入点使 $user 含标签——实际上 username 原样来自 $_GET，mysqli_real_escape_string 不处理 HTML 元字符，因此第 28 行存在反射型 XSS 的可能：$user 直接来自 $_GET['username']，仅经 stripslashes 与 SQL 转义，未做 HTML 编码即拼入 <p> 回显。但该回显仅在登录成功（mysqli_num_rows==1）时触发，需要有效凭据，利用条件受限，且属于 DVWA 教学靶场代码，CVE 价值低，故不单独立 finding，仅作为线索记录。第 5 行 checkToken 与第 41 行 generateSessionToken 的实现不在 code_pack 内，无法确认 CSRF 防护是否有效。第 33 行 sleep(rand(0,3)) 为弱随机延时，非安全敏感。未发现命令执行、文件包含、反序列化、SSRF 等汇点。配置类候选（weak_hash：第 16 行 md5 用于口令哈希，属 CWE-328，但为靶场代码且无外部可利用链）不单独立项。

未覆盖 / 证据缺口：
- checkToken/generateSessionToken 定义不在 code_pack，CSRF 防护有效性无法确认
- 无数据库配置、无路由/部署信息，无法确认 010.php 实际暴露路径与认证要求
- 第 28 行 $user 反射型 XSS 需登录成功才触发，条件受限未立项
- 第 16 行 md5 口令哈希属 weak_hash 线索，无外部利用链未立项

## 3. Findings

### F-1: 010.php 登录查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`010.php:18-20`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 010.php 提交登录参数，源码在 010.php:8 从请求中读取 username（候选 source 记为 query `username`），该值未经任何转义或参数化即被拼接到 010.php:19 的 SQL 语句 "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';" 中，随后在 010.php:20 由 mysqli_query 执行。虽然 010.php:15 对 $pass 调用了 mysqli_real_escape_string，但 $user 变量在拼接前没有任何对应的转义或白名单校验，因此单引号可闭合 user 字段的字符串字面量，注入任意 SQL 片段（如 ' OR '1'='1 绕过认证，或 UNION 读取其他表）。校验无效的原因是该处采用字符串拼接构造 SQL，而非预处理语句/参数绑定。

**source / sink**

- source：query `username`（010.php:8）
- sink：010.php:20 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `010.php:8` | 从 query `username` 读取外部输入 | 污点进入 query |  |
| 2 | `010.php:20` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /010（GET）的 SQL 注入 POC。注入点：GET 参数 username；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/010'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/010?username=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-7034f0a19983`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可绕过登录认证并读取数据库任意数据（users 表及其他可访问表），结合 010.php:20 的 die(mysqli_error(...)) 错误回显还可进行报错型注入与数据库结构探测；若数据库账户权限过高，可能进一步导致数据篡改。属于未授权即可触发的数据泄露/认证绕过。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：注入点为登录请求参数 username，属公开 HTTP 入口，无需认证即可访问；利用链闭合：010.php:8 读取输入 → 010.php:19 字符串拼接 → 010.php:20 mysqli_query 执行，中间无有效净化（$user 未转义），且错误信息经 die() 回显，便于构造盲注/报错注入。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用 mysqli 预处理语句与参数绑定（prepare + bind_param），彻底避免字符串拼接；若必须拼接，对 $user 使用 mysqli_real_escape_string 并配合严格白名单校验；同时移除 010.php:20 中向客户端回显 mysqli_error 的 die() 分支，改为记录服务端日志并返回通用错误；数据库账户遵循最小权限，仅授予必要表的 SELECT 权限。

**验证说明**

静态证据：入口 GET /010；source=query/username；sink=010.php:20；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在登录表单/请求中提交 username=' OR '1'='1（或 UNION 载荷）→ 010.php:8 读取该参数到 $user → 010.php:19 直接拼入 WHERE user = '$user' → 010.php:20 mysqli_query 执行被篡改的查询 → 返回全部用户行或注入结果，实现认证绕过与数据读取。
PocWriter 建议（未采纳，缺少端点 /010）：针对 010.php:20 的 SQL 注入 POC。源码在 010.php 第 20 行将外部输入拼接进 SQL 查询，注入通道为 GET 参数 username，触发按钮字段为 Submit。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /010）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 010.php:20，外部输入来自 GET 参数 username，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。所有请求中的主机统一为 TARGET:8080，实际测试时替换为授权目标。步骤 2/3 需保持同一会话上下文（无状态 GET，无需 Cookie）。

### F-2: 010.php 口令使用 MD5 哈希（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`010.php:15-16`
- **来源**：`rule`

**描述**

010.php:16 对登录口令执行 $pass = md5($pass)，即使用 MD5 这一已被证明存在碰撞且计算速度极快的哈希算法处理口令。该值随后在 010.php:19 被拼入 SQL 与数据库中的口令字段比较，说明 MD5 被用于口令存储/校验的安全用途。MD5 无盐、无迭代、无工作因子，攻击者一旦获取口令哈希即可通过彩虹表或 GPU 高速暴力破解还原明文。注意：此处属于弱哈希（CWE-328），而非弱加密算法（CWE-327）。

**source / sink**

- source：repository `md5(`（010.php）
- sink：010.php:16 	$pass = md5( $pass );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `010.php:16` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 010.php:16 的弱哈希静态证据 POC。源码第 16 行对密码变量 $pass 使用 md5() 进行哈希，属于弱哈希算法（CWE-328），无需发送 HTTP 请求，仅做源码级证据记录。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 010.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-949d40928ae7`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

口令哈希可被离线快速破解，导致用户账户凭据泄露；若数据库泄露，攻击者可批量还原弱口令并横向登录，造成账户接管。

**CVE / CWE 论证**

CWE-328（使用弱哈希算法）。该弱点为配置/实现型，无需 HTTP 污点链即可成立：证据为 010.php:16 明文调用 md5() 处理口令，且 010.php:19 将其用于口令比对，属安全用途。外部可达性体现在登录接口可被反复调用以获取/验证哈希行为；利用前提是攻击者能获取哈希（如通过同文件 GEN-7034f0a19983 的 SQL 注入读取 users 表），两者可组合放大影响。证据等级为源码推断（llm_inferred）。

**修复建议**

改用专为口令设计的慢哈希算法，如 PHP 的 password_hash()（PASSWORD_BCRYPT 或 PASSWORD_ARGON2ID）配合 password_verify()，并为每个口令使用随机盐；对存量 MD5 哈希在用户下次登录时透明升级；同时修复同文件的 SQL 注入以避免哈希外泄。

**验证说明**

静态证据：入口 GET /010；source=repository/md5(；sink=010.php:16；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户登录时口令经 010.php:16 md5() 处理 → 010.php:19 拼入 SQL 与库中 MD5 值比较 → 攻击者通过 SQL 注入（GEN-7034f0a19983）导出 users 表哈希 → 离线彩虹表/暴力破解还原明文口令 → 账户接管。
POC 备注：纯静态证据型 POC，不发送任何请求，不执行脚本。证据片段：010.php 第 15 行 mysqli_real_escape_string 处理 $pass，第 16 行 $pass = md5($pass)。

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
| `weak_crypto` | CWE-327 |  | 1 |
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
| safety_guard | 安全防护 | 4.25 | 是 |
| surface_mapper | 攻击面测绘 | 7.9 | 是 |
| deep_finder | LLM 深挖 | 4.4 | 是 |
| candidate_screener | 候选筛选 | 3.24 | 是 |
| vulnerability_analyzer | 漏洞分析 | 9.02 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.94 | 是 |
| coordinator | 管线协调 | 6.07 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
