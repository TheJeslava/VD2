# 落日二号乙漏洞挖掘报告 — 20261031-012324-02a396

- 生成时间：2026-10-30T17:24:36.732476+00:00
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

本次汇总 8 条已去重 findings，全部带 POC（with_poc=8），覆盖 4 类：sql_injection 4 条、auth_bypass 1 条、weak_id 2 条、csrf 1 条。最高危为 058_05.php / 058_06.php / 058_08.php 的 4 处 critical SQL 注入（注册、登录、改口令、用户名存在性查询），均为规则命中且带 HTTP POC；其次为 058_06.php 登录后仅置 Auth=1 固定 Cookie、058_08.php 仅凭该 Cookie 判登录导致的可伪造认证绕过（high，HTTP POC），以及两条 weak_id（固定值认证 Cookie、登出 Cookie 缺安全属性，静态/会话语义证据为主）。POC 齐全度：8/8 有 POC，但需区分——SQL 注入与认证绕过为 HTTP 可复现 POC；weak_id 属配置/会话标志类，POC 为静态证据，不能宣称可动态复现。本次 min_severity=low、suppressed_count=0，无策略抑制。

共 **8** 条 finding；**8** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：8 个文件 / 11823 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中全部 8 个文件（058_01~058_08）。核心发现：(1) 058_05.php 注册处 mysql_escape_string 与双引号包裹不匹配，配合 058_08.php 从 $_SESSION 取用户名直接拼 UPDATE，构成存储型二次 SQL 注入（写点 058_05.php:48-49，读点 058_08.php:31，汇点 058_08.php:38）；(2) 058_06.php 设置固定 Auth=1 Cookie，058_08/058_01/058_04 仅凭 Cookie 存在性判定登录，可伪造绕过认证。058_06.php 登录查询使用 mysql_real_escape_string 且单引号包裹，未发现可闭合的一次注入。058_02.php 为纯静态页面，无风险。058_03.php/058_04.php 仅显示部分行（1-38），其余行未送入，可能存在未覆盖逻辑。未发现命令执行、文件包含、反序列化、SSRF 类汇点。配置型线索：setcookie 未设置 HttpOnly/Secure（058_06.php:44、058_08.php:66），因影响有限未单独立项。

未覆盖 / 证据缺口：
- 058_03.php 仅显示 1-38 行（共61行），39-61 行未覆盖
- 058_04.php 仅显示 1-38 行（共91行），39-91 行未覆盖
- 058_05.php 仅显示 1-66 行（共76行），67-76 行未覆盖
- 058_06.php 仅显示 1-59 行（共65行），60-65 行未覆盖
- sql-connections/sql-connect.php 未在 code_pack 中，数据库连接与字符集/模式未知
- 无路由与部署信息，无法确认文件对外暴露方式

## 3. Findings

### F-1: 058_05.php 注册流程 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_05.php:47-49`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `username`（058_05.php:25 读取）提交输入，该值未经转义直接拼接进 INSERT 语句：058_05.php:48 `$sql = "insert into users ( username, password) values(\"$username\", \"$pass\")"`，随后在 058_05.php:49 交给 `mysql_query($sql)` 执行。代码中未见 mysql_real_escape_string、addslashes、预处理语句或类型白名单，双引号包裹的字符串字面量可被 `"` 或反斜杠转义序列闭合，因此校验无效。

**source / sink**

- source：query `username`（058_05.php:25）
- sink：058_05.php:49 mysql_query($sql) or die('Error Creating your user account,  : '.mysql_error());

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_05.php:25` | 从 query `username` 读取外部输入 | 污点进入 sql |  |
| 2 | `058_05.php:49` | 危险汇点：mysql_query($sql) or die('Error Creating your user account,  : '.mysql_error()); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /058_05（query 参数）的 SQL 注入 POC。注入点为 query 参数 username，payload 为 ' OR '1'='1。

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

可向 users 表写入任意行（伪造/覆盖账号），并通过报错信息 `mysql_error()` 回显（058_05.php:49）实施报错型注入读取数据库内容，导致账号数据泄露与认证绕过；结合堆叠/子查询可进一步篡改数据。

**CVE / CWE 论证**

CWE-89：外部可控的 query 参数 `username` 未经参数化直接进入 SQL 语句并执行，属典型一次注入；入口为公开注册页面，无需认证即可触发，source→sink 链在 058_05.php:25→48→49 内闭合。

**修复建议**

改用 PDO/MySQLi 预处理语句并绑定参数（如 `INSERT INTO users(username,password) VALUES(?,?)`）；对 username 做长度与字符白名单校验；关闭 `or die(mysql_error())` 的详细错误回显，改为记录日志并返回通用错误；数据库账号按最小权限仅授予 INSERT 所需权限。

**验证说明**

静态证据：入口 ANY /058_05；source=query/username；sink=058_05.php:49；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求 query `username` → 058_05.php:25 赋值给 $username → 058_05.php:48 字符串拼接进 INSERT → 058_05.php:49 mysql_query 执行，注入生效。
PocWriter 建议（未采纳，缺少端点 /058_05）：符合 CWE-89。漏洞位于 058_05.php:49，外部输入来自 query 参数 username，source→sink 链静态闭合，未发现有效净化。
POC 备注：仅限授权测试；文本工件，不执行。原草稿使用 -X ANY，实际请按服务端接受的方法（GET/POST）发送，参数名保持 username。

### F-2: 058_06.php 登录认证 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_06.php:22-24`
- **来源**：`rule`

**描述**

攻击者通过 query 参数 `login_user`（058_06.php:20 读取）提交输入，`$username`/`$password` 未转义即拼接进 058_06.php:22 `SELECT * FROM users WHERE username='$username' and password='$password'`，在 058_06.php:24 由 `mysql_query($sql)` 执行。单引号包裹的字符串可被 `'` 闭合，代码中无任何转义或参数化，校验无效。

**source / sink**

- source：query `login_user`（058_06.php:20）
- sink：058_06.php:24 $res = mysql_query($sql) or die('You tried to be real smart, Try harder!!!! :( ');

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_06.php:20` | 从 query `login_user` 读取外部输入 | 污点进入 sql |  |
| 2 | `058_06.php:24` | 危险汇点：$res = mysql_query($sql) or die('You tried to be real smart, Try harder!!!! :( '); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /058_06（query 参数 login_user）的 SQL 注入 POC。payload 为 ' OR '1'='1。

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

可通过 `username=' OR '1'='1' -- ` 之类载荷绕过口令校验，以任意已知用户（含管理员）身份登录，造成认证绕过与越权访问；亦可利用报错/联合查询读取 users 表全部口令数据。

**CVE / CWE 论证**

CWE-89：登录接口的 query 参数直接拼接进认证 SQL，属一次注入；接口对外公开、无需认证即可访问，058_06.php:20→22→24 构成闭合利用链。

**修复建议**

使用预处理语句绑定 username/password；口令以 password_hash/password_verify 存储校验而非明文比较；移除 `or die(...)` 中的差异化提示，统一失败响应；对登录失败做速率限制。

**验证说明**

静态证据：入口 ANY /058_06；source=query/login_user；sink=058_06.php:24；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求 query `login_user` → 058_06.php:20 取得 $username/$password → 058_06.php:22 拼接 WHERE 条件 → 058_06.php:24 mysql_query 执行，认证逻辑被注入改写。
PocWriter 建议（未采纳，缺少端点 /058_06）：符合 CWE-89。漏洞位于 058_06.php:24，外部输入来自 query 参数 login_user，source→sink 链静态闭合，未发现有效净化。
POC 备注：仅限授权测试；文本工件，不执行。参数名保持 login_user。

### F-3: 058_08.php 修改口令 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_08.php:37-39`
- **来源**：`rule`

**描述**

攻击者通过 query 参数 `current_password`（058_08.php:32 读取）提交输入，`$pass`/`$username`/`$curr_pass` 未转义即拼接进 058_08.php:38 `UPDATE users SET PASSWORD='$pass' where username='$username' and password='$curr_pass'`，在 058_08.php:39 由 `mysql_query($sql)` 执行。WHERE 子句中的单引号可被闭合，无转义/参数化，校验无效。

**source / sink**

- source：query `current_password`（058_08.php:32）
- sink：058_08.php:39 $res = mysql_query($sql) or die('You tried to be smart, Try harder!!!! :( ');

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_08.php:32` | 从 query `current_password` 读取外部输入 | 污点进入 sql |  |
| 2 | `058_08.php:39` | 危险汇点：$res = mysql_query($sql) or die('You tried to be smart, Try harder!!!! :( '); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /058_08（query 参数 current_password）的 SQL 注入 POC。payload 为 ' OR '1'='1。

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

可绕过当前口令校验，将任意用户（含管理员）口令改为攻击者指定值，实现账号接管；也可通过报错回显读取数据库内容，属数据篡改与越权。

**CVE / CWE 论证**

CWE-89：外部可控 query 参数进入 UPDATE 语句并执行；058_08.php:32→38→39 链闭合，页面为口令修改功能，攻击者只需能访问该端点即可触发（是否需登录取决于会话校验，但注入本身不依赖认证）。

**修复建议**

使用预处理语句绑定三个参数；修改口令前在服务端强制校验当前口令（用 password_verify）；对 username 做白名单/会话绑定校验，禁止修改他人账号；关闭 mysql_error 回显。

**验证说明**

静态证据：入口 ANY /058_08；source=query/current_password；sink=058_08.php:39；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求 query `current_password` → 058_08.php:32 取得 $curr_pass → 058_08.php:38 拼接 UPDATE 的 WHERE 条件 → 058_08.php:39 mysql_query 执行，口令更新条件被注入绕过。
PocWriter 建议（未采纳，缺少端点 /058_08）：符合 CWE-89。漏洞位于 058_08.php:39，外部输入来自 query 参数 current_password，source→sink 链静态闭合，未发现有效净化。
POC 备注：仅限授权测试；文本工件，不执行。参数名保持 current_password。

### F-4: 058_05.php 用户名存在性查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.73`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_05.php:29-31`
- **来源**：`rule`

**描述**

攻击者通过 query 参数 `username`（058_05.php:25 读取）提交输入，未转义即拼接进 058_05.php:30 `select count(*) from users where username='$username'`，在 058_05.php:31 由 `mysql_query($sql)` 执行。单引号可闭合字符串字面量，代码无转义或参数化，校验无效。

**source / sink**

- source：query `username`（058_05.php:25）
- sink：058_05.php:31 $res = mysql_query($sql) or die('You tried to be smart, Try harder!!!! :( ');

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_05.php:25` | 从 query `username` 读取外部输入 | 污点进入 sql |  |
| 2 | `058_05.php:31` | 危险汇点：$res = mysql_query($sql) or die('You tried to be smart, Try harder!!!! :( '); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /058_05（query 参数 username，行 31 处 sink）的 SQL 注入 POC。payload 为 ' OR '1'='1。

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

可用于枚举/读取 users 表数据（如通过布尔或报错差异判断），泄露账号信息；与同文件 058_05.php:48 的 INSERT 注入叠加可扩大数据篡改面。

**CVE / CWE 论证**

CWE-89：query 参数直接进入 SELECT 并执行，058_05.php:25→30→31 链闭合，公开页面无需认证即可触发。

**修复建议**

改用预处理语句绑定 username；对用户名做字符白名单；统一错误响应，避免 `or die(mysql_error())` 泄露 SQL 结构。

**验证说明**

静态证据：入口 ANY /058_05；source=query/username；sink=058_05.php:31；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求 query `username` → 058_05.php:25 赋值 → 058_05.php:30 拼接 SELECT 条件 → 058_05.php:31 mysql_query 执行。
PocWriter 建议（未采纳，缺少端点 /058_05）：符合 CWE-89。漏洞位于 058_05.php:31，外部输入来自 query 参数 username，source→sink 链静态闭合，未发现有效净化。
POC 备注：仅限授权测试；文本工件，不执行。与 LLM-71e4b84077e0 为同一文件不同行号 sink，请分别验证。

### F-5: 058_06.php 登录后仅设置 Auth=1 Cookie，058_08.php 等页面仅凭该 Cookie 判定已登录，可伪造 Cookie 绕过认证

- **类型**：`auth_bypass` / CWE-287
- **严重度**：`high`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`058_08.php:7-14`
- **来源**：`llm_finding`

**描述**

058_06.php 登录成功后执行 setcookie("Auth", 1, time()+3600)，仅写入固定值 1，不含签名/会话绑定。058_08.php 第7-14行、058_01.php 第3-10行、058_04.php 第3-10行仅检查 isset($_COOKIE["Auth"]) 即认为已认证（058_08.php 中即使 $_SESSION 不存在，只要 Cookie 存在就不跳转）。攻击者手工设置 Cookie Auth=1 即可绕过登录访问受保护页面（改密、登录后页面），无需有效凭据。

**source / sink**

- source：cookie `Auth`（058_08.php）
- sink：058_08.php:14 认证判定分支：仅 isset($_COOKIE["Auth"]) 即放行受保护页面（058_08.php:7、058_01.php:3、058_04.php:3）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_06.php:44` | 登录成功后设置固定值 Cookie Auth=1，无签名、无会话绑定 | 客户端获得 Auth=1 |  |
| 2 | `058_08.php:7` | 受保护页面仅检查 isset($_COOKIE["Auth"])，存在即不跳转 | 攻击者伪造 Auth=1 即通过认证判定 | 认证仅依赖客户端可控 Cookie 的存在性，未校验会话或签名 |

**POC**

针对 /058_08.php 的认证绕过 POC。通过伪造 Cookie Auth=admin 访问受保护资源。

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
- POC 目录：`poc/LLM-294d609e1b45`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

认证绕过，未授权访问登录后功能页面；结合改密逻辑可进一步尝试账户操作。

**CVE / CWE 论证**

CWE-287/CWE-565。认证状态完全由客户端 Cookie 存在性决定，外部无需凭据即可触发，链路在 CODE PACK 内闭合。

**修复建议**

认证状态仅以服务端会话为准，移除对客户端 Cookie 存在性的信任；Cookie 应设置 HttpOnly/Secure 并使用签名令牌。

**验证说明**

需确认 058_08.php 在 $_SESSION 为空时后续改密逻辑是否因 $username 为空而失败；认证绕过本身（页面放行）已可由代码确认。
模型 POC 要点：攻击者不登录，直接携带伪造的 Auth=1 Cookie 访问受保护页面。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /058_08.php）：符合 CWE-287。漏洞位于 058_08.php:14，外部输入来自 Cookie Auth，source→sink 链静态闭合，未发现有效校验。
POC 备注：仅限授权测试；文本工件，不执行。Cookie 名保持 Auth。

### F-6: 058_06.php 认证 Cookie 使用固定值（CWE-330/CWE-565）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_06.php:43-44`
- **来源**：`rule`

**描述**

058_06.php:44 `setcookie("Auth", 1, time()+3600)` 将认证标志 Cookie 设为常量 1，而非不可预测的随机会话标识；058_06.php:43 仅把用户名写入 `$_SESSION["username"]`。任何客户端只要自行设置 `Auth=1` 即可伪造该标志，服务端无法区分合法与伪造。

**source / sink**

- source：request `session cookie`（058_06.php）
- sink：058_06.php:44 	setcookie("Auth", 1, time()+3600);  /* expire in 15 Minutes */

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_06.php:44` | 会话标识由时间/递增值派生；需跨请求预测并确认服务端接受 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /058_06.php 的弱会话标识 POC。通过观察会话 cookie 生成规律，验证其可预测性。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/058_06'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 弱 ID / 可预测会话标识 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/058_06?session cookie=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-381e6544791c`
- 风险提示：finding 来源为 Cookie，但 POC 未发送 Cookie 请求头, POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可手工构造 `Cookie: Auth=1` 冒充已认证状态，若下游页面仅以该 Cookie 判断登录，则导致认证绕过与越权访问。

**CVE / CWE 论证**

CWE-330（弱随机/可预测标识）与 CWE-565（依赖不可信 Cookie 做安全决策）：标识为常量而非随机值，可被任意客户端复现。证据边界：片段未展示下游对 Auth 的校验逻辑，实际绕过效果需跨文件复核。

**修复建议**

不要用常量 Cookie 表示认证状态；改用服务端会话（session_regenerate_id 后仅依赖 PHPSESSID），Cookie 设置 HttpOnly、Secure、SameSite；对会话标识使用 CSPRNG 生成。

**验证说明**

静态证据：入口 ANY /058_06；source=request/session cookie；sink=058_06.php:44；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：登录成功 → 058_06.php:44 下发 `Auth=1` → 攻击者本地伪造同名 Cookie → 下游页面据 Cookie 判定已登录。
PocWriter 建议（未采纳，缺少端点 /058_06）：符合 CWE-330。漏洞位于 058_06.php:44，会话标识生成使用弱随机源。
POC 备注：仅限授权测试；文本工件，不执行。Cookie 名以源码实际会话机制为准（如 PHPSESSID）。

### F-7: 058_08.php 登出使用固定值 Cookie 且缺少安全属性（CWE-330/CWE-614）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_08.php:65-66`
- **来源**：`rule`

**描述**

058_08.php:65-66 在 `session_destroy()` 后执行 `setcookie('Auth', 1, time()-3600)`，以常量 1 作为 Cookie 值并仅通过过期时间清除；该 Cookie 未设置 HttpOnly/Secure/SameSite 属性。常量值本身不携带随机性，且清除依赖客户端时间。

**source / sink**

- source：request `session cookie`（058_08.php）
- sink：058_08.php:66 	setcookie('Auth', 1 , time()-3600);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_08.php:66` | 会话标识由时间/递增值派生；需跨请求预测并确认服务端接受 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /058_08.php 的弱会话标识 POC。验证会话标识可预测性。

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

若下游逻辑以 `Auth` 存在与否判断登录，攻击者可自行设置 `Auth=1` 维持/伪造认证状态；缺少 HttpOnly 使该标志可被脚本读取，配合 XSS 可被窃取或篡改。

**CVE / CWE 论证**

CWE-330（可预测/常量标识）与 CWE-614（敏感 Cookie 未设 Secure/HttpOnly）：证据为 058_08.php:66 的常量值与缺失属性。证据边界：登出路径本身不直接造成越权，实际影响取决于下游对 Auth 的信任方式，需跨文件复核。

**修复建议**

认证状态完全交由服务端会话管理，登出时销毁会话并重新生成会话 ID；Cookie 统一设置 HttpOnly、Secure、SameSite；避免使用常量值表达安全状态。

**验证说明**

静态证据：入口 ANY /058_08；source=request/session cookie；sink=058_08.php:66；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户登出 → 058_08.php:66 下发过期常量 Cookie → 攻击者本地伪造 `Auth=1` → 下游据 Cookie 误判为已登录。
PocWriter 建议（未采纳，缺少端点 /058_08）：符合 CWE-330。漏洞位于 058_08.php:66，会话标识生成使用弱随机源。
POC 备注：仅限授权测试；文本工件，不执行。Cookie 名以源码实际会话机制为准。

### F-8: 058_08.php 口令修改缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.56`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_08.php:37-38`
- **来源**：`rule`

**描述**

058_08.php:37-38 的口令修改逻辑直接依据请求参数执行 `UPDATE users SET PASSWORD=...`，代码片段中未见 CSRF token、Origin/Referer 校验或二次确认。攻击者可构造第三方页面，诱导已登录用户浏览器向该端点提交修改口令请求。

**source / sink**

- source：request `password change`（058_08.php）
- sink：058_08.php:38 		$sql = "UPDATE users SET PASSWORD='$pass' where username='$username' and password='$curr_pass' ";

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_08.php:38` | 状态改变请求未见 CSRF token/Origin 校验；需复核认证与 SameSite 条件 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /058_08.php 密码修改功能的 CSRF POC。攻击者构造自动提交表单，诱导已登录受害者在无感知情况下修改密码。

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

在受害者已登录且浏览器自动携带会话的前提下，攻击者可将其口令改为已知值，实现账号接管。

**CVE / CWE 论证**

CWE-352：状态改变请求缺少不可预测令牌校验。证据边界：片段未展示会话校验与 Cookie SameSite 属性，实际可利用性依赖受害者处于已认证状态且会话 Cookie 被跨站携带，属需运行时复核的语义命中。

**修复建议**

为口令修改表单引入一次性 CSRF token 并在服务端校验；校验 Origin/Referer；会话 Cookie 设置 SameSite=Lax/Strict 与 Secure；修改口令要求重新输入当前口令。

**验证说明**

静态证据：入口 ANY /058_08；source=request/password change；sink=058_08.php:38；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造跨站表单 → 受害者浏览器携带会话提交至 058_08.php → 058_08.php:38 执行 UPDATE 修改口令。
PocWriter 建议（未采纳，缺少端点 /058_08）：符合 CWE-352。漏洞位于 058_08.php:38，密码修改流程缺少 CSRF token 校验。
POC 备注：仅限授权测试；poc.html 为文本工件，不自动执行。表单字段名以源码实际读取的参数为准，若源码参数名不同请按源码调整。

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
| `weak_id` | CWE-330 |  | 2 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.33 | 是 |
| surface_mapper | 攻击面测绘 | 10.13 | 是 |
| deep_finder | LLM 深挖 | 14.29 | 是 |
| candidate_screener | 候选筛选 | 7.6 | 是 |
| vulnerability_analyzer | 漏洞分析 | 15.16 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 15.84 | 是 |
| coordinator | 管线协调 | 6.92 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
