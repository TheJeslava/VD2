# 落日二号乙漏洞挖掘报告 — 20261031-215117-05355b

- 生成时间：2026-10-31T13:52:46.798021+00:00
- 输入：`$WORKSPACE\暴风星云裂\058.zip`
- 输入模式：`zip`
- SHA256：`673852f18914330b130b5f444ee77aa68b61c515b2cf8b8a257468a33775f45f`
- 文件：8（文本 8）
- 语言：php(8)
- 框架：未识别
- 端点：0
- 版本：1.5.0-ver5
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总 8 条已去重 findings，全部带 POC（with_poc=8）。最高危为 4 条 critical 级 SQL 注入：058_06.php 登录查询（GEN-2e336c5d86ca）、058_08.php 修改密码 UPDATE（GEN-14a19460b45a）、058_05.php 用户计数查询（GEN-b07a62da291f）与 058_05.php 注册 INSERT（GEN-7923d3edceea），均为规则命中、有 HTTP POC 文本。其次为 1 条 high 级认证绕过（LLM-294d609e1b45，058_08.php 仅凭客户端可控 Cookie Auth=1 通过认证，可导致任意用户密码重置/账户接管，属 llm_inferred 推断级证据）与 2 条 high 级 weak_id（SEM-381e6544791c、SEM-84e9d7c625f8，固定值认证 Cookie 且缺安全属性，CWE-330/CWE-565），后者为静态/会话语义证据 POC，不能宣称可动态复现。另有 1 条 medium 级 CSRF（SEM-e3f6e1c06f4d，058_08.php 改密无 CSRF 防护）。POC 齐全度：8/8 均有 POC 文本，但需区分——SQL 注入、auth_bypass、csrf 具备 HTTP 请求语义 POC；weak_id 属静态/会话证据 POC。所有结论均为源码审计与静态推断，未经动态验证。

共 **8** 条 finding；**8** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：8 个文件 / 11823 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中全部 8 个文件（058_01~058_08）。058_05.php 与 058_08.php 存在 source→sink 链：058_08.php 认证守卫仅依赖客户端 Cookie Auth，构成认证绕过/账户接管链；058_05.php 使用 mysql_escape_string 拼接 SQL，存在宽字节注入风险（依赖字符集）。058_06.php 的 sqllogin 使用 mysql_real_escape_string 且登录逻辑本身为示例，未发现可闭合注入链。058_01/03/04 为访问控制与展示页，058_02/07 为静态表单页，未发现弱哈希/弱随机/硬编码凭据证据。未覆盖：sql-connect.php 等 include 文件不在 code_pack，无法确认连接字符集与数据库配置；无 Web 服务器配置，无法确认文件可达性。

未覆盖 / 证据缺口：
- ../sql-connections/sql-connect.php 未提供，无法确认数据库字符集与连接方式
- 无 Web 服务器/路由配置，文件可达性未确认
- 058_03.php 与 058_04.php 仅显示前 38 行，后续行未覆盖
- 058_05.php 仅显示 1-66 行，67-76 行未覆盖

## 3. Findings

### F-1: 058_06.php 登录查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_06.php:22-24`
- **来源**：`rule`

**描述**

攻击者通过登录表单提交的 username/password 参数（058_06.php:20 处从请求读取 login_user 相关输入）进入 $username、$password 变量，在 058_06.php:22 被直接拼接进 SQL 语句 "SELECT * FROM users WHERE username='$username' and password='$password'"，随后在 058_06.php:24 交给 mysql_query($sql) 执行。代码未使用 mysql_real_escape_string、预处理语句或类型约束，单引号可闭合字符串字面量，因此校验无效。

**source / sink**

- source：query `login_user`（058_06.php:20）
- sink：058_06.php:24 $res = mysql_query($sql) or die('You tried to be real smart, Try harder!!!! :( ');

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_06.php:20` | 从 query `login_user` 读取外部输入 | 污点进入 sql |  |
| 2 | `058_06.php:24` | 危险汇点：$res = mysql_query($sql) or die('You tried to be real smart, Try harder!!!! :( '); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /058_06（POST）的 SQL 注入 POC。注入点：POST 参数 login_user；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/058_06'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/058_06' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'login_user=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-2e336c5d86ca`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可绕过登录认证（以 ' OR '1'='1 之类载荷返回任意用户记录），并可进一步通过 UNION/布尔盲注读取 users 表及其他库表数据，导致账户凭据泄露与数据库数据窃取；错误信息经 die() 回显亦辅助注入探测。

**CVE / CWE 论证**

CWE-89：外部可控输入未经参数化直接拼入 SQL 并执行，属典型 SQL 注入。攻击面为 Web 登录接口，无需认证即可访问，source（请求参数）→ 拼接（058_06.php:22）→ sink（058_06.php:24 mysql_query）链路闭合，外部可达。

**修复建议**

改用 PDO/MySQLi 预处理语句并绑定参数（如 $stmt = $pdo->prepare('SELECT * FROM users WHERE username=? AND password=?')）；对输入做长度与字符白名单校验；数据库账户最小权限；关闭详细错误回显，改为记录日志。

**验证说明**

静态证据：入口 POST /058_06；source=query/login_user；sink=058_06.php:24；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在登录请求中提交恶意 username/password → 058_06.php:20 读取为 $username/$password → 058_06.php:22 字符串拼接构造 $sql → 058_06.php:24 mysql_query($sql) 执行 → 返回被篡改的查询结果或泄露数据。
PocWriter 建议（未采纳，缺少端点 /058_06）：针对 058_06.php:24 的 SQL 注入 POC。源码将 POST 参数 login_user 直接拼入 SQL 查询，未做参数化/转义，可通过布尔恒真条件绕过登录校验。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_06）：符合 CWE-89。漏洞位于 058_06.php:24，外部输入来自 POST 参数 login_user，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标统一使用 TARGET 占位符。

### F-2: 058_08.php 修改密码 UPDATE 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_08.php:37-39`
- **来源**：`rule`

**描述**

攻击者通过修改密码表单提交的 current_password（以及 pass、username）参数，在 058_08.php:32 被读取后于 058_08.php:38 直接拼接进 "UPDATE users SET PASSWORD='$pass' where username='$username' and password='$curr_pass'"，并在 058_08.php:39 由 mysql_query($sql) 执行。未做转义或参数化，单引号可闭合 password='$curr_pass' 条件。

**source / sink**

- source：query `current_password`（058_08.php:32）
- sink：058_08.php:39 $res = mysql_query($sql) or die('You tried to be smart, Try harder!!!! :( ');

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_08.php:32` | 从 query `current_password` 读取外部输入 | 污点进入 sql |  |
| 2 | `058_08.php:39` | 危险汇点：$res = mysql_query($sql) or die('You tried to be smart, Try harder!!!! :( '); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /058_08（POST）的 SQL 注入 POC。注入点：POST 参数 current_password；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/058_08'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/058_08' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'current_password=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-14a19460b45a`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可篡改 WHERE 条件从而修改任意用户（含管理员）口令，实现账户接管与越权；亦可利用报错/布尔差异进行数据外带，造成数据库完整性破坏。

**CVE / CWE 论证**

CWE-89：外部输入进入 UPDATE 语句拼接并执行。该功能位于已登录后的密码修改流程，但注入本身源于未参数化拼接，链路 source（058_08.php:32）→ 拼接（058_08.php:38）→ sink（058_08.php:39）闭合；认证要求取决于部署，注入缺陷本身成立。

**修复建议**

使用预处理语句绑定 $pass、$username、$curr_pass；对 username 做白名单校验；修改密码前要求校验旧口令并使用服务端会话身份而非请求中的 username；最小权限数据库账户。

**验证说明**

静态证据：入口 POST /058_08；source=query/current_password；sink=058_08.php:39；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交修改密码请求 → 058_08.php:32 读取 current_password 等参数 → 058_08.php:38 拼接 UPDATE 语句 → 058_08.php:39 mysql_query 执行 → 任意用户口令被改写或数据泄露。
PocWriter 建议（未采纳，缺少端点 /058_08）：针对 058_08.php:39 的 SQL 注入 POC。源码将 POST 参数 current_password 直接拼入 SQL 语句，可通过恒真条件绕过密码校验。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_08）：符合 CWE-89。漏洞位于 058_08.php:39，外部输入来自 POST 参数 current_password，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标统一使用 TARGET 占位符。

### F-3: 058_05.php 用户计数查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_05.php:29-31`
- **来源**：`rule`

**描述**

攻击者在 058_05.php:25 处提交的 username 参数被读入 $username，于 058_05.php:30 拼接为 "select count(*) from users where username='$username'"，并在 058_05.php:31 由 mysql_query($sql) 执行。无转义、无参数化，单引号可闭合条件。

**source / sink**

- source：query `username`（058_05.php:25）
- sink：058_05.php:31 $res = mysql_query($sql) or die('You tried to be smart, Try harder!!!! :( ');

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_05.php:25` | 从 query `username` 读取外部输入 | 污点进入 sql |  |
| 2 | `058_05.php:31` | 危险汇点：$res = mysql_query($sql) or die('You tried to be smart, Try harder!!!! :( '); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 058_05.php:31 的 SQL 注入 POC（路由 /058_05）。源码将 POST 参数 username 直接拼入 SQL 查询。目标地址使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/058_05'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/058_05' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-b07a62da291f`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可通过布尔/联合注入枚举 users 表内容（用户名、口令哈希），造成敏感数据泄露；亦可探测数据库结构，为后续攻击提供情报。

**CVE / CWE 论证**

CWE-89：请求参数直接拼入 SELECT 并执行。source（058_05.php:25）→ 拼接（058_05.php:30）→ sink（058_05.php:31）链路闭合，Web 接口外部可达。

**修复建议**

改用预处理语句绑定 username；对用户名实施字符白名单与长度限制；统一错误处理，避免 mysql_error 泄露。

**验证说明**

静态证据：入口 POST /058_05；source=query/username；sink=058_05.php:31；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 username → 058_05.php:25 读取 → 058_05.php:30 拼接 count 查询 → 058_05.php:31 mysql_query 执行 → 计数结果被操纵或数据外带。
PocWriter 建议（未采纳，缺少端点 /058_05）：符合 CWE-89。漏洞位于 058_05.php:31，外部输入来自 POST 参数 username，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标统一使用 TARGET 占位符。

### F-4: 058_05.php 用户注册 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_05.php:47-49`
- **来源**：`rule`

**描述**

同一 username 输入（058_05.php:25）在注册分支被用于 058_05.php:48 的 "insert into users ( username, password) values(\"$username\", \"$pass\")"，并在 058_05.php:49 由 mysql_query 执行。使用双引号包裹但同样未转义，攻击者可用双引号闭合并注入额外列值或子查询。

**source / sink**

- source：query `username`（058_05.php:25）
- sink：058_05.php:49 mysql_query($sql) or die('Error Creating your user account,  : '.mysql_error());

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_05.php:25` | 从 query `username` 读取外部输入 | 污点进入 sql |  |
| 2 | `058_05.php:49` | 危险汇点：mysql_query($sql) or die('Error Creating your user account,  : '.mysql_error()); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /058_05（POST）的 SQL 注入 POC。注入点：POST 参数 username；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/058_05'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/058_05' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-7923d3edceea`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可插入任意用户记录（含自定义口令/权限字段），实现未授权账户创建与权限提升；结合 mysql_error 回显可进行报错注入读取数据。

**CVE / CWE 论证**

CWE-89：外部输入进入 INSERT 拼接并执行，且错误信息经 mysql_error() 回显。source（058_05.php:25）→ 拼接（058_05.php:48）→ sink（058_05.php:49）闭合，注册接口外部可达、无需认证。

**修复建议**

使用预处理语句绑定 username/password；对用户名做白名单校验；口令使用 password_hash 存储；禁止将 mysql_error 输出到响应。

**验证说明**

静态证据：入口 POST /058_05；source=query/username；sink=058_05.php:49；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交注册请求 → 058_05.php:25 读取 username → 058_05.php:48 拼接 INSERT → 058_05.php:49 mysql_query 执行 → 注入任意记录或触发报错泄露。
PocWriter 建议（未采纳，缺少端点 /058_05）：针对 058_05.php:49 的 SQL 注入 POC。源码在 49 行处将 POST 参数 username 拼入 SQL 语句。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_05）：符合 CWE-89。漏洞位于 058_05.php:49，外部输入来自 POST 参数 username，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标统一使用 TARGET 占位符。

### F-5: 058_08.php 密码修改页仅凭客户端可控 Cookie Auth=1 即通过认证，导致任意用户密码重置（账户接管）

- **类型**：`auth_bypass` / CWE-287
- **严重度**：`high`
- **置信度**：`0.72`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`058_08.php:7-14`
- **来源**：`llm_finding`

**描述**

058_08.php 的访问控制只检查 `isset($_COOKIE["Auth"])`（第 7 行），而该 Cookie 在 058_06.php 第 44 行由服务端以固定值 1 下发、无签名无校验。攻击者无需登录，只要在请求中手工带上 `Cookie: Auth=1` 即可通过第 7-14 行的守卫，进入密码修改逻辑。随后第 31 行 `$username = $_SESSION["username"]` 取当前会话用户名，第 38 行构造 `UPDATE users SET PASSWORD='$pass' where username='$username' and password='$curr_pass'`。由于守卫不校验会话身份，攻击者可用自己注册/已知的账号建立会话（或直接利用会话固定），再借 Cookie 绕过进入改密页；更关键的是守卫逻辑本身把「是否已认证」完全交给客户端 Cookie，属于典型的信任边界错误，可导致对任意已登录会话的密码修改流程被未授权触发。

**source / sink**

- source：cookie `Auth`（058_08.php）
- sink：058_08.php:14 058_08.php:38 mysql_query(UPDATE users SET PASSWORD=...)

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_08.php:7` | 守卫仅判断 Cookie Auth 是否存在，存在即跳过重定向 | 攻击者设置 Cookie: Auth=1 | isset 只判断存在性，不校验值/签名，任意值均可通过 |
| 2 | `058_08.php:31` | 从会话取用户名作为 UPDATE 的 where 条件 | $username = $_SESSION["username"] |  |
| 3 | `058_08.php:38` | 执行 UPDATE 修改密码 | SQL 语句拼接 $pass/$curr_pass |  |

**POC**

针对 /058_08.php（POST）的 认证绕过 POC。注入点：Cookie: Auth；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/058_08.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 认证绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/058_08.php' \
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

认证守卫完全依赖客户端 Cookie，攻击者可绕过登录校验进入改密流程，结合会话可重置账户密码，造成账户接管。

**CVE / CWE 论证**

CWE-287/CWE-565：认证决策基于客户端可控 Cookie，无服务端会话校验，外部无需真实凭据即可通过守卫。

**修复建议**

移除对 Cookie Auth 的信任，仅以服务端 $_SESSION 校验身份；Cookie 应加签名或改用服务端会话。

**验证说明**

需确认 058_08.php 实际部署路径与 058_06.php 的会话建立是否可被攻击者自行完成；UPDATE 的 where 仍绑定会话用户名，接管范围受会话限制。
模型 POC 要点：携带伪造 Cookie 直接访问改密接口，配合已建立的会话完成密码修改
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /058_08.php）：针对 058_08.php:14 的认证绕过 POC。源码在 14 行处依据 Cookie Auth 的值判定身份，未做完整性校验，伪造 Auth=admin 即可冒充管理员。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_08.php）：符合 CWE-287。漏洞位于 058_08.php:14，外部输入来自 Cookie Auth，source→sink 链静态闭合，未见有效校验，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标统一使用 TARGET 占位符。

### F-6: 058_06.php 认证 Cookie 使用固定值且缺少安全属性（CWE-330/CWE-565）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_06.php:43-44`
- **来源**：`rule`

**描述**

058_06.php:43-44 在登录成功后设置 $_SESSION["username"] 并执行 setcookie("Auth", 1, time()+3600)，即认证标志 Auth 恒为常量 1，且未设置 HttpOnly/Secure/SameSite 属性。该 Cookie 不携带不可预测的会话标识，任何能设置同名 Cookie 的客户端都可伪造认证状态（取决于服务端是否仅以 Auth 存在性判定登录）。

**source / sink**

- source：session `dvwaSession`（058_06.php）
- sink：058_06.php:44 	setcookie("Auth", 1, time()+3600);  /* expire in 15 Minutes */

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_06.php:44` | 会话标识由时间/递增值派生；需跨请求预测并确认服务端接受 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /058_06（POST）的 弱 ID / 可预测会话标识 POC。注入点：POST 会话建立请求；连续请求比较 dvwaSession Cookie；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/058_06'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **在保持同一会话的情况下第一次 POST，记录 Set-Cookie**

```http
curl -sS -i -b "${cookie_jar}" -c "${cookie_jar}" -X POST 'http://TARGET:8080/058_06' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：返回 dvwaSession 等会话 Cookie，记录其值

3. **保持同一会话再次 POST，并比较两次会话 Cookie**

```http
curl -sS -i -b "${cookie_jar}" -c "${cookie_jar}" -X POST 'http://TARGET:8080/058_06' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：Cookie 值出现连续递增/可预测序列

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-381e6544791c`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若服务端仅检查 Auth Cookie 是否存在，攻击者可自行设置 Auth=1 绕过认证；常量值也使会话固定/伪造风险上升，可能导致未授权访问 logged-in.php 等受保护页面。

**CVE / CWE 论证**

CWE-330（使用不充分的随机值）与 CWE-565（依赖不可信 Cookie 做安全决策）：认证标志为可预测常量。证据限于 058_06.php:43-44 片段，服务端校验逻辑未在片段中出现，属证据不足部分，需结合 logged-in.php 复核。

**修复建议**

使用框架会话机制生成高熵会话 ID，登录后 session_regenerate_id(true)；认证状态仅存于服务端会话，不以客户端常量 Cookie 判定；Cookie 设置 HttpOnly、Secure、SameSite。

**验证说明**

静态证据：入口 POST /058_06；source=session/dvwaSession；sink=058_06.php:44；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者观察到 Auth=1 常量 → 在浏览器或请求中直接设置 Cookie Auth=1 → 若服务端仅校验其存在性则进入已登录状态 → 未授权访问受保护功能。
PocWriter 建议（未采纳，缺少端点 /058_06）：针对 058_06.php:44 的弱会话 ID POC。源码在 44 行处生成 dvwaSession Cookie，其值可预测（连续/可枚举），攻击者可推测他人会话。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_06）：符合 CWE-330。漏洞位于 058_06.php:44，会话标识 dvwaSession 生成可预测，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标统一使用 TARGET 占位符；需连续请求比较 Cookie 序列。

### F-7: 058_08.php 注销逻辑使用常量 Cookie 且缺少安全属性（CWE-330/CWE-565）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_08.php:65-66`
- **来源**：`rule`

**描述**

058_08.php:65-66 在注销时执行 session_destroy() 并 setcookie('Auth', 1, time()-3600) 使 Cookie 过期。认证标志仍为常量 1，未使用不可预测值，也未设置 HttpOnly/Secure/SameSite；该模式表明认证状态依赖客户端可控的固定 Cookie。

**source / sink**

- source：session `dvwaSession`（058_08.php）
- sink：058_08.php:66 	setcookie('Auth', 1 , time()-3600);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_08.php:66` | 会话标识由时间/递增值派生；需跨请求预测并确认服务端接受 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /058_08（POST）的 弱 ID / 可预测会话标识 POC。注入点：POST 会话建立请求；连续请求比较 dvwaSession Cookie；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/058_08'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **在保持同一会话的情况下第一次 POST，记录 Set-Cookie**

```http
curl -sS -i -b "${cookie_jar}" -c "${cookie_jar}" -X POST 'http://TARGET:8080/058_08' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：返回 dvwaSession 等会话 Cookie，记录其值

3. **保持同一会话再次 POST，并比较两次会话 Cookie**

```http
curl -sS -i -b "${cookie_jar}" -c "${cookie_jar}" -X POST 'http://TARGET:8080/058_08' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：Cookie 值出现连续递增/可预测序列

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-84e9d7c625f8`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

与登录侧一致，若服务端以 Auth Cookie 存在性判定认证，攻击者可伪造 Auth=1 获得已登录状态，导致未授权访问与账户冒用。

**CVE / CWE 论证**

CWE-330/CWE-565：认证标志为可预测常量。证据仅覆盖 058_08.php:65-66 的注销片段，服务端认证校验逻辑未提供，属证据不足部分。

**修复建议**

认证状态完全由服务端会话维护，注销时销毁会话并清除会话 Cookie；Cookie 设置 HttpOnly、Secure、SameSite；避免以常量 Cookie 表示登录状态。

**验证说明**

静态证据：入口 POST /058_08；source=session/dvwaSession；sink=058_08.php:66；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者设置 Auth=1 Cookie → 服务端若仅检查其存在即视为已登录 → 未授权访问受保护页面或功能。
PocWriter 建议（未采纳，缺少端点 /058_08）：针对 058_08.php:66 的弱会话 ID POC。源码在 66 行处生成 dvwaSession Cookie，其值可预测，攻击者可推测他人会话。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_08）：符合 CWE-330。漏洞位于 058_08.php:66，会话标识 dvwaSession 生成可预测，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标统一使用 TARGET 占位符；需连续请求比较 Cookie 序列。

### F-8: 058_08.php 修改密码功能缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.56`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_08.php:37-38`
- **来源**：`rule`

**描述**

058_08.php:37-38 的修改密码逻辑在收到 Change 请求后直接执行 UPDATE users SET PASSWORD，代码片段中未见 CSRF token、Origin/Referer 校验或二次确认。攻击者可构造第三方页面自动提交表单，使已登录受害者在不知情下修改口令。

**source / sink**

- source：query `Change`（058_08.php）
- sink：058_08.php:38 		$sql = "UPDATE users SET PASSWORD='$pass' where username='$username' and password='$curr_pass' ";

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_08.php:38` | 状态改变请求未见 CSRF token/Origin 校验；需复核认证与 SameSite 条件 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /058_08（GET）的 跨站请求伪造 POC。注入点：GET 参数 Change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/058_08'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/058_08?Change=Change&password_new=SUNSET_NEW&password_conf=SUNSET_NEW'
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/SEM-e3f6e1c06f4d`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

已认证用户被诱导提交请求后口令被改为攻击者已知值，导致账户接管；若受害者权限较高则影响扩大。

**CVE / CWE 论证**

CWE-352：状态改变请求缺乏不可预测令牌校验。外部可达性依赖受害者已登录会话，属跨站场景；证据仅覆盖 058_08.php:37-38 片段，会话 Cookie 的 SameSite 属性与认证前置条件未在片段中体现，属证据不足部分。

**修复建议**

为修改密码表单加入每会话随机 CSRF token 并在服务端校验；校验 Origin/Referer；会话 Cookie 设置 SameSite=Lax/Strict、Secure、HttpOnly；敏感操作要求重新输入旧口令。

**验证说明**

静态证据：入口 GET /058_08；source=query/Change；sink=058_08.php:38；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者搭建恶意页面自动向 058_08.php 提交 Change 请求 → 受害者浏览器携带会话 Cookie 发送 → 058_08.php:38 执行 UPDATE 修改口令 → 账户被接管。
PocWriter 建议（未采纳，缺少端点 /058_08）：针对 058_08.php:38 的 CSRF POC。修改密码接口通过 GET 参数 Change/password_new/password_conf 触发，无 CSRF token 校验，可诱导已登录用户浏览器发起请求改密。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_08）：符合 CWE-352。漏洞位于 058_08.php:38，改密操作通过 GET 触发且无 CSRF token，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标统一使用 TARGET 占位符；受害者会话需由测试者自行提供。

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
| `blind_sql_injection` | CWE-89 |  | 0 |
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
| safety_guard | 安全防护 | 4.24 | 是 |
| surface_mapper | 攻击面测绘 | 13.16 | 是 |
| deep_finder | LLM 深挖 | 12.76 | 是 |
| candidate_screener | 候选筛选 | 10.34 | 是 |
| vulnerability_analyzer | 漏洞分析 | 17.08 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 20.95 | 是 |
| coordinator | 管线协调 | 10.27 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
