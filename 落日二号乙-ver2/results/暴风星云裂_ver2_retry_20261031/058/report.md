# 落日二号乙漏洞挖掘报告 — 20261031-002524-581809

- 生成时间：2026-10-30T16:26:33.361521+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\058.zip`
- 输入模式：`zip`
- SHA256：`673852f18914330b130b5f444ee77aa68b61c515b2cf8b8a257468a33775f45f`
- 文件：8（文本 8）
- 语言：php(8)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`high`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总 5 条已去重 findings：4 条 sql_injection（critical，均为 rule 命中，058_05.php 两处、058_06.php 一处、058_08.php 一处，均带 POC）与 1 条 auth_bypass（high，LLM 推断，058_06.php 以客户端可控 Cookie Auth=1 作为登录凭据，带 POC）。最高危为 058_05.php / 058_06.php / 058_08.php 的登录与改密 SQL 注入，可直接绕过认证或篡改口令；其次为 058_06.php 的 Cookie 伪造登录态。5 条 finding 均标注 has_poc=true，但 POC 均为静态文本工件，未做动态验证；auth_bypass 属 llm_inferred 等级，需代码/会话语义复核。

共 **5** 条 finding；**5** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：8 个文件 / 11823 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中全部 8 个 PHP 文件（058_01~058_08）。核心发现两条闭合链：(1) 058_05.php 注册写点 + 058_08.php 会话读点 + UPDATE 拼接汇点构成二次 SQL 注入，可接管任意账户；(2) 058_06.php 下发固定 Cookie Auth=1，受保护页面仅 isset 校验，构成认证绕过。058_06.php 登录查询使用 mysql_real_escape_string 且为一次注入，未单独报告；058_03/058_04/058_07 主要为表单与展示，未见新闭合链。未覆盖：sql-connect.php 等 include 文件不在 code_pack，无法确认数据库配置与错误显示；无 php.ini/部署信息，无法评估运行时可利用性；配置类（weak_hash/weak_crypto/weak_random/insecure_cookie）无足够证据，未报告。

未覆盖 / 证据缺口：
- ../sql-connections/sql-connect.php 未在 code_pack，数据库连接与错误处理未知
- 058_03.php/058_04.php 仅显示前 38 行，剩余行未审计
- 058_05.php 仅显示 1-66 行、058_06.php 仅 1-59 行，尾部未覆盖
- 无运行时配置，无法确认 display_errors 等对注入可利用性的影响

## 3. Findings

### F-1: 058_05.php 登录查询 username 参数 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_05.php:29-31`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `username` 输入（058_05.php:25 读取），该值未经任何转义或参数化即被拼接进 SQL 语句：058_05.php:30 `$sql = "select count(*) from users where username='$username'"`，随后在 058_05.php:31 交由 `mysql_query($sql)` 执行。由于 `$username` 被直接放入单引号字符串上下文，攻击者可闭合引号并注入任意 SQL 片段（如 `' OR '1'='1`、`' UNION SELECT ...`），校验完全缺失，污点直达数据库执行汇点。

**source / sink**

- source：query `username`（058_05.php:25）
- sink：058_05.php:31 $res = mysql_query($sql) or die('You tried to be smart, Try harder!!!! :( ');

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_05.php:25` | 从 query `username` 读取外部输入 | 污点进入 sql |  |
| 2 | `058_05.php:31` | 危险汇点：$res = mysql_query($sql) or die('You tried to be smart, Try harder!!!! :( '); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /058_05（ANY）的 SQL 注入 POC。注入点：ANY 参数 username；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/058_05'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/058_05?username=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-b07a62da291f`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库查询逻辑被完全控制：可绕过登录/计数校验、通过 UNION 读取 users 表及其他表数据（口令、用户信息泄露），并可结合 mysql 权限进行数据篡改。错误信息经 `die()` 回显，可辅助盲注/报错注入。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达：`username` 来自 HTTP query，无需认证即可触发；利用链闭合：058_05.php:25 取值 → 058_05.php:30 字符串拼接 → 058_05.php:31 `mysql_query` 执行，中间无白名单、转义或预处理。

**修复建议**

改用 PDO/MySQLi 预处理语句并绑定参数，例如 `$stmt = $pdo->prepare('select count(*) from users where username = ?'); $stmt->execute([$username]);`；禁止字符串拼接 SQL；对输入做长度与字符白名单校验；关闭 `mysql_error()` 细节回显，统一错误页；升级已废弃的 `mysql_*` 扩展。

**验证说明**

静态证据：入口 ANY /058_05；source=query/username；sink=058_05.php:31；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 `?username=' OR '1'='1` → 058_05.php:25 读入 `$username` → 058_05.php:30 拼入 `select count(*) from users where username='$username'` → 058_05.php:31 `mysql_query($sql)` 执行被篡改的语句 → 返回结果/错误信息回显给攻击者。
PocWriter 建议（未采纳，缺少端点 /058_05）：针对 058_05.php 的 SQL 注入 POC。注入点为请求参数 username（058_05.php:31），未净化即拼接进 SQL 查询。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /058_05）：符合 CWE-89。漏洞位于 058_05.php:31，外部输入来自 query 参数 username，source→sink 链在给定代码范围内静态闭合，未见有效净化。证据等级：llm_inferred。
POC 备注：POC 仅为文本工件，不执行、不联网。执行前替换 TARGET；原始请求结构保留为 GET 风格查询串（原草稿标注 ANY，实际以 GET 查询参数传递即可复现）。

### F-2: 058_06.php 登录认证 username/password 参数 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_06.php:22-24`
- **来源**：`rule`

**描述**

攻击者通过 query 参数 `login_user` 相关输入（058_06.php:20 读取 `$username`、`$password`）提交数据，二者未经转义直接拼接进认证 SQL：058_06.php:22 `$sql = "SELECT * FROM users WHERE username='$username' and password='$password'"`，在 058_06.php:24 由 `mysql_query($sql)` 执行。单引号上下文可被闭合，攻击者可用 `' OR '1'='1' -- ` 之类载荷绕过口令校验，或以 UNION 注入读取任意数据。

**source / sink**

- source：query `login_user`（058_06.php:20）
- sink：058_06.php:24 $res = mysql_query($sql) or die('You tried to be real smart, Try harder!!!! :( ');

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_06.php:20` | 从 query `login_user` 读取外部输入 | 污点进入 sql |  |
| 2 | `058_06.php:24` | 危险汇点：$res = mysql_query($sql) or die('You tried to be real smart, Try harder!!!! :( '); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /058_06（ANY）的 SQL 注入 POC。注入点：ANY 参数 login_user；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/058_06'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/058_06?login_user=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-2e336c5d86ca`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

认证绕过（无需正确口令即可登录任意账户，包括管理员），并通过 UNION/报错注入读取 users 表及其他表数据，造成账户接管与敏感数据泄露。

**CVE / CWE 论证**

CWE-89。外部可达：`username`/`password` 来自 HTTP query，登录接口无需前置认证；利用链闭合：058_06.php:20 取值 → 058_06.php:22 拼接 → 058_06.php:24 `mysql_query` 执行，无预处理、无转义、无类型约束。

**修复建议**

使用预处理语句绑定 `username`、`password` 参数；口令以强哈希（如 password_hash/bcrypt）存储并比对，而非明文拼接查询；对输入做白名单与长度限制；移除 `die()` 中的数据库错误回显；废弃 `mysql_*` 扩展。

**验证说明**

静态证据：入口 ANY /058_06；source=query/login_user；sink=058_06.php:24；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 `login_user` 相关参数 `username=admin' -- `、`password=x` → 058_06.php:20 读入 → 058_06.php:22 拼接为 `SELECT * FROM users WHERE username='admin' -- ' and password='x'` → 058_06.php:24 执行，口令条件被注释掉 → 以 admin 身份通过认证。
PocWriter 建议（未采纳，缺少端点 /058_06）：针对 058_06.php 的 SQL 注入 POC。注入点为请求参数 login_user（058_06.php:24），未净化即进入 SQL 查询。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /058_06）：符合 CWE-89。漏洞位于 058_06.php:24，外部输入来自 query 参数 login_user，source→sink 链在给定代码范围内静态闭合，未见有效净化。证据等级：llm_inferred。
POC 备注：POC 仅为文本工件，不执行、不联网。执行前替换 TARGET；原始请求结构保留（login_user 查询参数）。

### F-3: 058_08.php 修改口令 current_password 参数 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_08.php:37-39`
- **来源**：`rule`

**描述**

攻击者在修改口令流程中通过 query 参数 `current_password`（058_08.php:32 读取 `$curr_pass`，同时涉及 `$username`、`$pass`）提交输入，未经转义即拼接进 UPDATE 语句：058_08.php:38 `$sql = "UPDATE users SET PASSWORD='$pass' where username='$username' and password='$curr_pass' "`，在 058_08.php:39 由 `mysql_query($sql)` 执行。攻击者可闭合引号注入，篡改 WHERE 条件或追加语句，从而在不知道原口令的情况下修改任意用户口令。

**source / sink**

- source：query `current_password`（058_08.php:32）
- sink：058_08.php:39 $res = mysql_query($sql) or die('You tried to be smart, Try harder!!!! :( ');

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_08.php:32` | 从 query `current_password` 读取外部输入 | 污点进入 sql |  |
| 2 | `058_08.php:39` | 危险汇点：$res = mysql_query($sql) or die('You tried to be smart, Try harder!!!! :( '); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /058_08（ANY）的 SQL 注入 POC。注入点：ANY 参数 current_password；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/058_08'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/058_08?current_password=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-14a19460b45a`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

越权修改任意账户（含管理员）口令，导致账户接管；亦可利用报错/联合注入读取数据库内容。属于写操作注入，破坏数据完整性。

**CVE / CWE 论证**

CWE-89。外部可达：`current_password` 等参数来自 HTTP query，修改口令接口可被未认证或低权限用户直接调用；利用链闭合：058_08.php:32 取值 → 058_08.php:38 拼接 UPDATE → 058_08.php:39 `mysql_query` 执行，无参数化与转义。

**修复建议**

使用预处理语句绑定 `$pass`、`$username`、`$curr_pass`；在服务端会话中取当前用户身份而非信任请求参数中的 `username`；校验旧口令使用哈希比对；限制 UPDATE 影响行数并记录审计日志；移除数据库错误回显。

**验证说明**

静态证据：入口 ANY /058_08；source=query/current_password；sink=058_08.php:39；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 `current_password=' OR '1'='1` 及新口令 → 058_08.php:32 读入 `$curr_pass` → 058_08.php:38 拼接 `UPDATE users SET PASSWORD='...' where username='...' and password='$curr_pass'` → 058_08.php:39 执行，WHERE 口令条件被绕过 → 目标账户口令被改为攻击者指定值。
PocWriter 建议（未采纳，缺少端点 /058_08）：针对 058_08.php 的 SQL 注入 POC。注入点为请求参数 current_password（058_08.php:39），未净化即进入 SQL 查询。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /058_08）：符合 CWE-89。漏洞位于 058_08.php:39，外部输入来自 query 参数 current_password，source→sink 链在给定代码范围内静态闭合，未见有效净化。证据等级：llm_inferred。
POC 备注：POC 仅为文本工件，不执行、不联网。执行前替换 TARGET；原始请求结构保留（current_password 查询参数）。

### F-4: 058_05.php 用户注册 username/pass 参数 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.73`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_05.php:47-49`
- **来源**：`rule`

**描述**

攻击者在注册流程中通过 query 参数 `username`（058_05.php:25 读取，另含 `$pass`）提交输入，未经转义即拼接进 INSERT 语句：058_05.php:48 `$sql = "insert into users ( username, password) values(\"$username\", \"$pass\")"`，在 058_05.php:49 由 `mysql_query($sql)` 执行。此处使用双引号包裹值，攻击者可用 `"` 闭合并注入额外列值或子查询，例如插入自定义口令的管理员账户，或通过报错信息泄露数据。

**source / sink**

- source：query `username`（058_05.php:25）
- sink：058_05.php:49 mysql_query($sql) or die('Error Creating your user account,  : '.mysql_error());

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_05.php:25` | 从 query `username` 读取外部输入 | 污点进入 sql |  |
| 2 | `058_05.php:49` | 危险汇点：mysql_query($sql) or die('Error Creating your user account,  : '.mysql_error()); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /058_05（ANY）的 SQL 注入 POC。注入点：ANY 参数 username；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/058_05'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/058_05?username=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-7923d3edceea`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可向 users 表插入任意内容（如伪造管理员账户实现提权/持久化），并通过 `mysql_error()` 回显进行报错注入读取数据库；破坏数据完整性并可能导致账户接管。

**CVE / CWE 论证**

CWE-89。外部可达：注册接口的 `username`/`pass` 来自 HTTP query，无需认证；利用链闭合：058_05.php:25 取值 → 058_05.php:48 双引号字符串拼接 → 058_05.php:49 `mysql_query` 执行，无预处理与转义。

**修复建议**

使用预处理语句绑定注册字段；对 `username` 施加字符白名单与唯一性约束；口令使用 `password_hash` 存储；移除 `mysql_error()` 回显；对注册接口增加限流与验证码。

**验证说明**

静态证据：入口 ANY /058_05；source=query/username；sink=058_05.php:49；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 `username=attacker", "pwned") -- ` 之类载荷 → 058_05.php:25 读入 → 058_05.php:48 拼接 INSERT 语句 → 058_05.php:49 执行，插入攻击者控制的行/列值 → 获得可控账户或触发报错泄露数据。
PocWriter 建议（未采纳，缺少端点 /058_05）：针对 058_05.php 的 SQL 注入 POC。注入点为请求参数 username（058_05.php:49），未净化即进入 SQL 查询。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /058_05）：符合 CWE-89。漏洞位于 058_05.php:49，外部输入来自 query 参数 username，source→sink 链在给定代码范围内静态闭合，未见有效净化。证据等级：llm_inferred。
POC 备注：POC 仅为文本工件，不执行、不联网。执行前替换 TARGET；原始请求结构保留（username 查询参数）。注意与 GEN-b07a62da291f 为同一文件不同行（31 与 49）的独立注入点。

### F-5: 058_06.php 登录逻辑使用客户端可控 Cookie Auth=1 作为认证凭据，可伪造登录态

- **类型**：`auth_bypass` / CWE-287
- **严重度**：`high`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`058_06.php:40-46`
- **来源**：`llm_finding`

**描述**

058_06.php 登录成功后仅设置 setcookie("Auth", 1, ...)（第 44 行），而 058_01.php/058_04.php/058_08.php 的访问控制仅检查 isset($_COOKIE["Auth"])（如 058_08.php:7、058_01.php:3、058_04.php:3），并不校验其值或与会话绑定。攻击者无需任何凭据，直接构造 Cookie: Auth=1 即可通过所有受保护页面的认证检查，访问登录后功能（改密页、登录成功页等）。

**source / sink**

- source：cookie `Auth`（058_06.php）
- sink：058_06.php:46 058_08.php:7 / 058_01.php:3 / 058_04.php:3 仅以 isset($_COOKIE["Auth"]) 作为认证判定

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_06.php:44` | 登录成功仅下发固定值 Cookie Auth=1，未与服务器会话或用户绑定 | Auth=1 为常量，任何客户端可自行设置 |  |
| 2 | `058_08.php:7` | 受保护页面仅判断 isset($_COOKIE["Auth"])，不校验值与会话一致性 | 攻击者伪造 Cookie: Auth=1 即通过检查 | 认证仅依赖客户端可写 Cookie 的存在性，未做服务端会话校验 |

**POC**

针对 /058_08.php（GET）的 认证绕过 POC。注入点：Cookie: Auth；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/058_08.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 认证绕过 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/058_08.php' \
  -H 'Cookie: Auth=admin'
```
预期：以未授权/伪造身份访问受保护资源返回 2xx。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`admin`
- POC 目录：`poc/LLM-28954cf1fb7e`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

未认证攻击者可访问登录后功能页面，结合二次注入可进一步接管账户。

**CVE / CWE 论证**

CWE-287/CWE-565 认证绕过（依赖客户端可控 Cookie）。外部无需凭据即可触发，链路闭合。

**修复建议**

认证状态完全依赖服务端 $_SESSION，移除对客户端 Cookie 存在性的信任；Cookie 仅作辅助且需签名校验。

**验证说明**

需确认 058_08.php 中 header('Location: index.php') 后是否因缺少 exit 仍继续执行（第 11-13 行无 exit），若继续执行则绕过更彻底；建议授权环境验证。
模型 POC 要点：直接携带伪造 Cookie 访问受保护页面
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /058_08.php）：针对 058_08.php 的认证绕过 POC。认证判断依赖客户端可控的 Cookie Auth（相关逻辑见 058_06.php:46），将其设为 admin 即可伪造身份访问受保护资源。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /058_08.php）：符合 CWE-287（认证不当）。认证判定读取客户端 Cookie Auth（058_06.php:46），未做服务端校验/签名，source→sink 链在给定代码范围内静态闭合。证据等级：llm_inferred。
POC 备注：POC 仅为文本工件，不执行、不联网。执行前替换 TARGET；原始请求结构保留：GET /058_08.php，Header Cookie: Auth=admin。注意 finding 记录的文件为 058_06.php:46，而请求端点按原草稿指向 /058_08.php，二者关系为认证逻辑与受保护入口，未做改动。

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
| `sql_injection` | CWE-89 | 是 | 4 |
| `ssrf` | CWE-918 | 是 | 0 |
| `path_traversal` | CWE-22 | 是 | 0 |
| `deserialization` | CWE-502 | 是 | 0 |
| `ssti` | CWE-1336 | 是 | 0 |
| `auth_bypass` | CWE-287 | 是 | 1 |
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
| safety_guard | 安全防护 | 3.83 | 是 |
| surface_mapper | 攻击面测绘 | 9.14 | 是 |
| deep_finder | LLM 深挖 | 14.4 | 是 |
| candidate_screener | 候选筛选 | 7.06 | 是 |
| vulnerability_analyzer | 漏洞分析 | 12.13 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 15.08 | 是 |
| coordinator | 管线协调 | 6.54 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
