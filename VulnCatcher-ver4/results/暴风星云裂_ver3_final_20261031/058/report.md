# 落日二号乙漏洞挖掘报告 — 20261031-014524-506a21

- 生成时间：2026-10-30T17:46:38.052486+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\058.zip`
- 输入模式：`zip`
- SHA256：`673852f18914330b130b5f444ee77aa68b61c515b2cf8b8a257468a33775f45f`
- 文件：8（文本 8）
- 语言：php(8)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总 7 条已去重 findings，覆盖 8 个独立 PHP 脚本（058_01.php–058_08.php），无框架、无路由配置，每个文件即一个入口脚本。最高危为 4 条 critical 级 SQL 注入：058_05.php 登录查询 username（行 31）与注册 INSERT username（行 49）、058_06.php 登录认证 login_user（行 24）、058_08.php 改口令 UPDATE current_password（行 39），均为规则命中且带 POC。其次为 058_06.php 的 auth_bypass（high，仅凭客户端可伪造 Auth Cookie 判定登录态且密码明文比对，可致账户接管）与 058_08.php 登出时设置可预测 Auth Cookie 的 weak_id（high，CWE-330），以及 058_08.php 改口令接口缺 CSRF 防护（medium，CWE-352）。7 条 findings 均标注 has_poc=true，但其中 weak_id 属静态/语义证据型 POC，不能宣称可动态复现；SQL 注入与 auth_bypass 的 POC 为 HTTP 文本工件，同样未经动态验证。本次未发现二次注入链，也未记录 prompt_injection 证据。

共 **7** 条 finding；**7** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：8 个文件 / 11823 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中全部 8 个文件（058_01 至 058_08）。058_05.php 注册接口使用 mysql_escape_string 转义后拼接 insert，存在二次注入写点；058_06.php 登录仅下发固定值 Auth Cookie，058_01/058_04/058_08 仅检查 Cookie 存在性，构成鉴权绕过；058_08.php 改密 UPDATE 语句拼接 $pass，与 058_05 的存储写点构成二次注入链。058_02.php 为纯静态页面无风险；058_03.php 仅含登录表单与 include；058_07.php 为注册表单页面，回显变量 $feedback_title_ns/$form_title_ns 来自 include 的 sql-connect.php（未在 code_pack 中），无法确认是否可控，未报告。未覆盖：sql-connections/sql-connect.php、login.php、logged-in.php、pass_change.php、failed.php 等被 include 或跳转的文件不在 code_pack 中，其过滤逻辑与数据库配置无法确认；无 php.ini/.htaccess，无法评估部署期设置。

未覆盖 / 证据缺口：
- sql-connections/sql-connect.php 未提供，无法确认数据库连接与字符集配置
- login.php/logged-in.php/pass_change.php/failed.php 未提供，无法确认登录与改密完整流程
- 058_07.php 中 $feedback_title_ns/$form_title_ns 来源不可见，可能存在 XSS 但证据不足
- 无部署配置，无法评估 Cookie 域与 HTTPS 设置

## 3. Findings

### F-1: 058_05.php 登录查询 username 参数 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_05.php:29-31`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `username` 输入（058_05.php:25 读取），该值未经任何转义或参数化即被拼接进 SQL 语句：058_05.php:30 `$sql = "select count(*) from users where username='$username'"`，随后在 058_05.php:31 交由 `mysql_query($sql)` 执行。由于 `$username` 被直接放入单引号字符串字面量中，攻击者可闭合引号注入任意 SQL 片段（如 `' OR '1'='1` 或 UNION 查询）。代码中未见 mysql_real_escape_string、addslashes、类型强制或预处理语句，校验完全缺失。

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

数据库查询逻辑被篡改，可绕过用户名存在性/计数校验，并通过 UNION 或布尔/报错注入读取 users 表（含口令字段）等任意数据，导致敏感数据泄露；结合 mysql_query 的堆叠/子查询能力还可能进一步影响数据完整性。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：注入点为 HTTP query 参数 `username`，无需认证即可访问该脚本路径；利用链闭合：source（058_05.php:25）→ 字符串拼接（058_05.php:30）→ 执行汇点（058_05.php:31），中间无有效净化，攻击者完全控制 SQL 结构。

**修复建议**

改用 PDO/MySQLi 预处理语句并绑定参数（如 `SELECT count(*) FROM users WHERE username = ?`）；若必须动态拼接，使用 mysql_real_escape_string 并配合白名单校验；对输入做长度与字符集约束；升级到受支持的数据库驱动，避免使用已废弃的 mysql_* 扩展。

**验证说明**

静态证据：入口 ANY /058_05；source=query/username；sink=058_05.php:31；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `?username=' OR '1'='1` → 058_05.php:25 读取 `username` → 058_05.php:30 拼接进 `select count(*) from users where username='...'` → 058_05.php:31 `mysql_query($sql)` 执行被篡改的 SQL，返回攻击者期望的计数/数据。
PocWriter 建议（未采纳，缺少端点 /058_05）：针对 058_05.php:31 的 SQL 注入 POC。注入点为查询参数 username，payload 为 ' OR '1'='1，目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_05）：符合 CWE-89。漏洞位于 058_05.php:31，外部输入来自 query 参数 username，source→sink 链静态闭合，未见有效净化，可远程触发。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标。

### F-2: 058_06.php 登录认证查询 login_user 参数 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_06.php:22-24`
- **来源**：`rule`

**描述**

攻击者通过 HTTP query 参数 `login_user`（058_06.php:20 读取）提交输入，`$username`/`$password` 未经转义即被拼接进认证 SQL：058_06.php:22 `$sql = "SELECT * FROM users WHERE username='$username' and password='$password'"`，在 058_06.php:24 由 `mysql_query($sql)` 执行。由于两个变量都位于单引号字面量内且无任何过滤，攻击者可用 `' OR '1'='1' -- ` 之类载荷绕过口令校验。

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

认证绕过：攻击者无需正确口令即可登录任意已知用户名账户（含管理员），造成越权访问；同时可通过 UNION/报错注入读取 users 表全部数据，导致凭据泄露。

**CVE / CWE 论证**

CWE-89。外部可达性：注入点为 HTTP query 参数 `login_user`，登录接口对外公开、无需前置认证；利用链闭合：source（058_06.php:20）→ 拼接（058_06.php:22）→ 执行（058_06.php:24），无净化环节。

**修复建议**

使用预处理语句绑定 `username` 与 `password` 参数；口令校验应使用 password_hash/password_verify 而非明文比较；对输入做白名单与长度限制；移除已废弃的 mysql_* API。

**验证说明**

静态证据：入口 ANY /058_06；source=query/login_user；sink=058_06.php:24；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 `?login_user=admin&password=' OR '1'='1' -- ` → 058_06.php:20 读取参数 → 058_06.php:22 拼接为 `SELECT * FROM users WHERE username='admin' and password='' OR '1'='1' -- '` → 058_06.php:24 执行，条件恒真，返回用户记录完成登录绕过。
PocWriter 建议（未采纳，缺少端点 /058_06）：针对 058_06.php:24 的 SQL 注入 POC。注入点为查询参数 login_user，payload 为 ' OR '1'='1，目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_06）：符合 CWE-89。漏洞位于 058_06.php:24，外部输入来自 query 参数 login_user，source→sink 链静态闭合，未见有效净化，可远程触发。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标。

### F-3: 058_05.php 用户注册 INSERT 语句 username 参数 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_05.php:47-49`
- **来源**：`rule`

**描述**

攻击者通过 HTTP query 参数 `username`（058_05.php:25 读取）提交输入，该值在注册分支被拼接进 INSERT 语句：058_05.php:48 `$sql = "insert into users ( username, password) values(\"$username\", \"$pass\")"`，并在 058_05.php:49 由 `mysql_query($sql)` 执行。变量被放入双引号字面量中且无转义，攻击者可闭合引号注入额外列值或子查询。

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

可向 users 表写入攻击者控制的数据（如以任意口令创建账户、篡改已有记录），并通过子查询/报错注入读取其他表数据；写入型注入还可用于持久化恶意数据，影响后续认证逻辑。

**CVE / CWE 论证**

CWE-89。外部可达性：注册功能通过 HTTP query 参数 `username` 对外暴露，无需认证；利用链闭合：source（058_05.php:25）→ 拼接（058_05.php:48）→ 执行（058_05.php:49），无净化。

**修复建议**

使用预处理语句绑定 username/password；对用户名实施字符白名单（如 `^[A-Za-z0-9_]{3,32}$`）；口令使用 password_hash 存储；避免将 mysql_error() 回显给客户端以减少报错注入信息泄露。

**验证说明**

静态证据：入口 ANY /058_05；source=query/username；sink=058_05.php:49；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 `?username=x\", \"p\"),(\"admin\",\"p\") -- ` 之类载荷 → 058_05.php:25 读取 → 058_05.php:48 拼接进 INSERT → 058_05.php:49 执行，插入攻击者构造的记录或触发子查询读取数据。
PocWriter 建议（未采纳，缺少端点 /058_05）：针对 058_05.php:49 的 SQL 注入 POC。注入点为查询参数 username，payload 为 ' OR '1'='1，目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_05）：符合 CWE-89。漏洞位于 058_05.php:49，外部输入来自 query 参数 username，source→sink 链静态闭合，未见有效净化，可远程触发。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标。

### F-4: 058_08.php 修改口令 UPDATE 语句 current_password 参数 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_08.php:37-39`
- **来源**：`rule`

**描述**

攻击者在修改口令流程中通过 HTTP query 参数 `current_password`（058_08.php:32 读取）提交输入，`$curr_pass`（及 `$pass`、`$username`）未经转义即被拼接进 UPDATE 语句：058_08.php:38 `$sql = "UPDATE users SET PASSWORD='$pass' where username='$username' and password='$curr_pass' "`，在 058_08.php:39 由 `mysql_query($sql)` 执行。攻击者可在 `current_password` 中注入 `' OR '1'='1` 使 WHERE 条件恒真，从而在不知道原口令的情况下修改任意用户口令。

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

越权修改任意账户（含管理员）口令，进而完全接管账户；也可通过子查询注入读取其他数据。属于高危认证/授权绕过与数据完整性破坏。

**CVE / CWE 论证**

CWE-89。外部可达性：口令修改接口通过 HTTP query 参数 `current_password` 暴露；利用链闭合：source（058_08.php:32）→ 拼接（058_08.php:38）→ 执行（058_08.php:39），无净化。注意：该接口通常需已登录会话，但注入本身不依赖认证即可触发 SQL 结构篡改。

**修复建议**

使用预处理语句绑定全部三个参数；修改口令前在服务端校验当前口令（password_verify）；对 username 做会话绑定校验，禁止从请求参数决定目标用户；移除 mysql_* 扩展。

**验证说明**

静态证据：入口 ANY /058_08；source=query/current_password；sink=058_08.php:39；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 `?current_password=' OR '1'='1&password=newpass&username=admin` → 058_08.php:32 读取 → 058_08.php:38 拼接为 `UPDATE users SET PASSWORD='newpass' where username='admin' and password='' OR '1'='1'` → 058_08.php:39 执行，admin 口令被改为 newpass。
PocWriter 建议（未采纳，缺少端点 /058_08）：针对 058_08.php:39 的 SQL 注入 POC。注入点为查询参数 current_password，payload 为 ' OR '1'='1，目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_08）：符合 CWE-89。漏洞位于 058_08.php:39，外部输入来自 query 参数 current_password，source→sink 链静态闭合，未见有效净化，可远程触发。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标。

### F-5: 058_06.php 登录逻辑仅凭客户端可伪造的 Auth Cookie 判定登录态，且密码明文比对导致任意账户接管

- **类型**：`auth_bypass` / CWE-287
- **严重度**：`high`
- **置信度**：`0.87`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`058_06.php:40-46`
- **来源**：`llm_finding`

**描述**

058_06.php 的 sqllogin() 用 mysql_real_escape_string 处理 login_user/login_password 后拼接 SQL，虽然转义阻止了经典注入，但登录成功后仅设置 setcookie("Auth", 1, time()+3600)，该 Cookie 值恒为 1、无签名、无 HttpOnly/Secure。058_01.php、058_04.php、058_08.php 的访问控制只检查 isset($_COOKIE["Auth"])，因此攻击者无需任何凭据，手工设置 Cookie Auth=1 即可通过所有受保护页面的鉴权检查，直接进入 logged-in.php / pass_change.php 等页面。此外 users 表密码以明文存储并明文比对（第 22 行），配合 058_08.php 的改密逻辑可进一步接管账户。

**source / sink**

- source：cookie `Auth`（058_06.php）
- sink：058_06.php:46 058_01.php:3-10 / 058_04.php:3-10 / 058_08.php:7-14 的 isset($_COOKIE["Auth"]) 鉴权判定

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_06.php:44` | 登录成功后服务端下发固定值 Cookie Auth=1，无签名、无随机性、无 HttpOnly/Secure 标志 | Auth=1（常量） |  |
| 2 | `058_01.php:3` | 受保护页面仅判断 Cookie 是否存在，不校验其值来源与完整性 | 攻击者手工构造 Auth=1 即满足条件 | 鉴权仅依赖客户端可写 Cookie 的存在性，无服务端会话绑定 |
| 3 | `058_04.php:26` | 通过鉴权后页面回显 $_SESSION["username"]，攻击者可直接访问改密表单 pass_change.php | 进入已登录上下文 |  |

**POC**

针对 /058_06.php（POST）的 认证绕过 POC。注入点：Cookie: Auth；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/058_06.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 认证绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/058_06.php' \
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

任意未认证攻击者绕过登录访问所有受保护功能，结合明文密码存储与改密逻辑可接管任意账户。

**CVE / CWE 论证**

CWE-287 Improper Authentication / CWE-565 Reliance on Cookies without Validation and Integrity Checking。外部 HTTP 可达，无需凭据，链路在 CODE PACK 内闭合。

**修复建议**

使用服务端会话作为唯一鉴权依据，删除基于固定值 Cookie 的判定；Cookie 设置 HttpOnly/Secure/SameSite；密码使用 password_hash/password_verify 存储校验。

**验证说明**

需确认部署环境中 058_01/058_04/058_08 与 058_06 同属一个应用且共享 Cookie 域；需确认 logged-in.php 等未在 code_pack 中的页面是否另有校验。
模型 POC 要点：不提供任何账号密码，直接伪造 Auth Cookie 访问受保护页面
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /058_06.php）：针对 058_06.php:46 的认证绕过 POC。通过伪造 Cookie Auth=admin 冒充管理员身份，目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_06.php）：符合 CWE-287。漏洞位于 058_06.php:46，外部输入来自 cookie Auth，source→sink 链静态闭合，未见有效校验，可远程触发。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标。

### F-6: 058_08.php 登出时设置可预测 Auth Cookie（CWE-330）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_08.php:65-66`
- **来源**：`rule`

**描述**

058_08.php:66 `setcookie('Auth', 1 , time()-3600);` 在登出流程中把 `Auth` Cookie 设为固定值 `1` 并置为过期。该 Cookie 值完全可预测且为常量，若服务端以 `Auth` 是否存在/取值判断认证状态，则攻击者可自行构造 `Auth=1` 伪造会话。需说明：片段仅显示登出路径，服务端如何校验 `Auth` 的证据不足，因此该条为基于语义模式的推断。

**source / sink**

- source：request `session cookie`（058_08.php）
- sink：058_08.php:66 	setcookie('Auth', 1 , time()-3600);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_08.php:66` | 会话标识由时间/递增值派生；需跨请求预测并确认服务端接受 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /058_08（ANY）的 弱 ID / 可预测会话标识 POC。注入点：ANY 参数 session cookie；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/058_08'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 弱 ID / 可预测会话标识 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/058_08?session cookie=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-84e9d7c625f8`
- 风险提示：finding 来源为 Cookie，但 POC 未发送 Cookie 请求头, POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

若服务端信任该 Cookie，攻击者可伪造认证状态实现未授权访问/账户接管；即使仅用于登出，固定常量值也削弱了会话标识的不可预测性。

**CVE / CWE 论证**

CWE-330（使用不充分的随机值）。外部可达性：Cookie 由客户端完全可控；利用链闭合性依赖服务端对 `Auth` 的校验逻辑，当前证据不足。

**修复建议**

不要使用常量或时间派生值作为认证标识；改用服务端会话（session_regenerate_id）并设置 HttpOnly、Secure、SameSite；登出时同时销毁服务端会话并清除 Cookie。

**验证说明**

静态证据：入口 ANY /058_08；source=request/session cookie；sink=058_08.php:66；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者手动设置 `Cookie: Auth=1` → 若服务端仅检查该 Cookie 存在/取值 → 获得已认证视图。
PocWriter 建议（未采纳，缺少端点 /058_08）：针对 058_08.php:66 的弱会话标识 POC。会话标识生成可预测/熵不足，攻击者可猜测或枚举有效会话。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_08）：符合 CWE-330。漏洞位于 058_08.php:66，会话标识生成使用弱随机/可预测来源，可远程触发。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标。

### F-7: 058_08.php 口令修改接口缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.5`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_08.php:37-38`
- **来源**：`rule`

**描述**

058_08.php:37-38 的口令修改逻辑直接依据请求参数执行 `UPDATE users SET PASSWORD=...`，代码片段中未见 CSRF token、Origin/Referer 校验或二次确认。攻击者可构造第三方页面，诱导已登录用户浏览器向该接口发起请求，从而在用户不知情下修改其口令。需注意：该结论依赖运行时条件（会话 Cookie 是否 SameSite、接口是否仅接受 POST），片段内无法完全确认。

**source / sink**

- source：request `password change`（058_08.php）
- sink：058_08.php:38 		$sql = "UPDATE users SET PASSWORD='$pass' where username='$username' and password='$curr_pass' ";

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_08.php:38` | 状态改变请求未见 CSRF token/Origin 校验；需复核认证与 SameSite 条件 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /058_08（ANY）的 跨站请求伪造 POC。注入点：ANY 参数 password change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/058_08'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/058_08?password change=%E8%87%AA%E5%8A%A8%E6%8F%90%E4%BA%A4%E8%A1%A8%E5%8D%95%EF%BC%88%E8%A7%81%20poc.html%EF%BC%89'
```
预期：受害者在已登录状态下自动提交表单，服务端接受状态变更。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/SEM-e3f6e1c06f4d`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

已登录用户被诱导后口令被静默修改，攻击者可接管账户；若目标为管理员则导致后台失陷。

**CVE / CWE 论证**

CWE-352。外部可达性：状态改变请求由浏览器跨站发起即可触达；利用链闭合性受限于会话 Cookie 属性与请求方法，证据不足部分已在描述中标注。

**修复建议**

为口令修改表单引入一次性 CSRF token 并在服务端校验；校验 Origin/Referer；会话 Cookie 设置 SameSite=Lax/Strict 与 Secure；敏感操作要求重新输入当前口令。

**验证说明**

静态证据：入口 ANY /058_08；source=request/password change；sink=058_08.php:38；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者页面自动向 058_08.php 提交 `password=...&username=...` → 受害者浏览器携带会话 Cookie 请求 → 058_08.php:38 执行 UPDATE，口令被改。
PocWriter 建议（未采纳，缺少端点 /058_08）：针对 058_08.php:38 的跨站请求伪造（CSRF）POC。密码修改表单缺少 CSRF token 校验，攻击者可诱导已登录用户自动提交表单完成密码变更。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_08）：符合 CWE-352。漏洞位于 058_08.php:38，密码修改逻辑缺少 CSRF token 校验，可远程触发。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。poc.html 需在授权测试环境中由测试者手动加载，TARGET 替换为授权目标。

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
| `csrf` | CWE-352 |  | 1 |
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
| `weak_id` | CWE-330 |  | 1 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.49 | 是 |
| surface_mapper | 攻击面测绘 | 10.72 | 是 |
| deep_finder | LLM 深挖 | 13.39 | 是 |
| candidate_screener | 候选筛选 | 8.87 | 是 |
| vulnerability_analyzer | 漏洞分析 | 15.72 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 14.75 | 是 |
| coordinator | 管线协调 | 7.75 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
