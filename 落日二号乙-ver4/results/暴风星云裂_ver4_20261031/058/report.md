# 落日二号乙漏洞挖掘报告 — 20261031-164900-ffab9c

- 生成时间：2026-10-31T08:50:34.639184+00:00
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

本次汇总 9 条已去重 findings，覆盖 8 个 PHP 文件（058_01.php~058_08.php，纯脚本无框架）。最高危为 4 条 critical 级 SQL 注入：058_05.php 登录查询（GEN-b07a62da291f，line_end 31）与注册 INSERT（GEN-7923d3edceea，line_end 49）、058_06.php 登录认证查询（GEN-2e336c5d86ca，line_end 24）、058_08.php 改密 UPDATE（GEN-14a19460b45a，line_end 39），均为字符串拼接 SQL，均带 POC。其次为 high 级认证缺陷：058_08.php 仅凭客户端可控 Cookie Auth 判定登录可绕过认证改任意用户密码（LLM-294d609e1b45，line_end 14），以及 058_06.php / 058_08.php 使用固定值 Auth=1 的 weak_id（SEM-381e6544791c line_end 44、SEM-84e9d7c625f8 line_end 66）。中危含 058_04.php 存储型 XSS（LLM-a8e9805999ee，line_end 27）与 058_08.php 改密缺 CSRF 防护（SEM-e3f6e1c06f4d，line_end 38）。9 条 findings 均标记 has_poc=true，但其中 weak_id 两条属静态/会话语义证据 POC，不能宣称可动态复现；SQL 注入、XSS、CSRF、auth_bypass 为 HTTP 型 POC 文本。所有结论均为源码审计推断（llm_inferred / rule），未做动态验证。

共 **9** 条 finding；**9** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：8 个文件 / 11823 字符；截断 0 个
- 模型新增候选：4 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中全部 8 个 PHP 文件（058_01~058_08）。核心发现集中在 058_05/058_06/058_08/058_04：认证门依赖客户端 Cookie Auth（058_08.php:7）可伪造；058_05.php 与 058_06.php 存在 SQL 拼接（mysql_escape_string/mysql_real_escape_string 上下文），宽字节绕过依赖连接字符集（sql-connect.php 未提供，属未闭合缺口）；058_04.php 回显会话用户名构成存储型 XSS。058_01/058_02/058_03/058_07 为静态页面或仅含表单，无独立可利用链。未发现命令执行、文件操作、反序列化、SSRF、模板注入汇点。配置型线索（弱哈希/弱随机/不安全 Cookie）在可见代码中未见 md5/sha1/rand 实现，仅 058_06.php:44 与 058_08.php:66 的 setcookie 未设 HttpOnly/Secure，单独不足以申报。

未覆盖 / 证据缺口：
- sql-connect.php 未在 code_pack 中，无法确认数据库连接字符集，宽字节注入成立性待验证
- 058_03.php 仅显示 1-38 行、058_04.php 仅 1-38 行、058_05.php 仅 1-66 行、058_06.php 仅 1-59 行，尾部逻辑未覆盖
- 无 HTTP 端点清单与部署配置，入口按文件推断
- 会话生成/固定机制未提供，058_08 认证绕过的会话获取路径待确认

## 3. Findings

### F-1: 058_05.php 登录查询 username 参数 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_05.php:29-31`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `username`（058_05.php:25 读取）提交任意字符串。该值未经转义直接拼接进 SQL 语句：058_05.php:30 `$sql = "select count(*) from users where username='$username'";`，随后在 058_05.php:31 交给 `mysql_query($sql)` 执行。代码中未见 mysql_real_escape_string、addslashes、预处理语句或类型强制转换，单引号闭合即可改变查询语义，因此校验无效。

**source / sink**

- source：query `username`（058_05.php:25）
- sink：058_05.php:31 $res = mysql_query($sql) or die('You tried to be smart, Try harder!!!! :( ');

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_05.php:25` | 从 query `username` 读取外部输入 | 污点进入 sql |  |
| 2 | `058_05.php:31` | 危险汇点：$res = mysql_query($sql) or die('You tried to be smart, Try harder!!!! :( '); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

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
- POC 目录：`poc/GEN-b07a62da291f`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库查询逻辑被篡改：可绕过用户名/口令校验、通过 UNION 或布尔/时间盲注读取 users 表（含 password 字段）等敏感数据，并可通过 mysql_error() 回显辅助枚举库表结构。属于数据泄露与认证绕过。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达：参数来自 HTTP query，无需认证即可访问该脚本；利用链闭合：source（058_05.php:25 username）→ 字符串拼接（058_05.php:30）→ mysql_query 执行（058_05.php:31），中间无净化。

**修复建议**

改用参数化查询（PDO/mysqli 预处理，绑定 :username）；若必须保留旧 mysql_* 接口，至少使用 mysql_real_escape_string 并加引号包裹；对 username 做长度与字符白名单校验；关闭 mysql_error() 的对外回显，统一错误页。

**验证说明**

静态证据：入口 POST /058_05；source=query/username；sink=058_05.php:31；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 `username=' OR '1'='1` 之类的 query 参数 → 058_05.php:25 读入 $username → 058_05.php:30 拼入 `where username='$username'` → 058_05.php:31 mysql_query 执行被篡改的 SQL → 返回计数/错误信息，泄露数据或绕过校验。
PocWriter 建议（未采纳，缺少端点 /058_05）：针对 058_05.php:31 的 SQL 注入 POC。注入点为 POST 参数 username，源码将其直接拼接进 SQL 查询，未做参数化或转义。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_05）：符合 CWE-89。漏洞位于 058_05.php:31，外部输入 username 未经净化直接进入 SQL 语句，source→sink 链静态闭合，可远程触发。
POC 备注：仅文本工件，不执行。poc.sh 中 TARGET 需由授权测试人员手动替换；禁止对生产环境运行。

### F-2: 058_05.php 用户注册 INSERT 语句 username/pass 拼接 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_05.php:47-49`
- **来源**：`rule`

**描述**

攻击者通过 query 参数 `username`（058_05.php:25 读取，$pass 同源表单字段）提交输入。058_05.php:48 将值直接拼入 INSERT：`$sql = "insert into users ( username, password) values(\"$username\", \"$pass\")";`，058_05.php:49 由 `mysql_query($sql)` 执行。双引号包裹但未转义，攻击者用 `"` 闭合即可注入；且 058_05.php:49 的 die 分支拼接 `mysql_error()`，进一步回显数据库错误。

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

可向 users 表写入任意行（如自建管理员账号），或通过报错/盲注读取数据库内容；结合错误回显可枚举表结构，导致认证绕过与数据篡改。

**CVE / CWE 论证**

CWE-89。外部可达：注册接口由 HTTP query 直接驱动，无需认证；利用链闭合：058_05.php:25 username → 058_05.php:48 字符串拼接 → 058_05.php:49 mysql_query 执行，无参数化或转义。

**修复建议**

使用预处理语句绑定 username/password；对输入做长度与字符白名单；口令应使用 password_hash() 存储而非明文拼接；移除 mysql_error() 回显。

**验证说明**

静态证据：入口 POST /058_05；source=query/username；sink=058_05.php:49；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 `username=x" , "y")-- -` 等载荷 → 058_05.php:25 读入 → 058_05.php:48 拼入 INSERT 的 values 列表 → 058_05.php:49 执行，插入攻击者控制的行或触发可回显的 SQL 错误。
PocWriter 建议（未采纳，缺少端点 /058_05）：针对 058_05.php:49 的 SQL 注入 POC。注入点为 POST 参数 username，源码在第二处查询中同样直接拼接该参数。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_05）：符合 CWE-89。漏洞位于 058_05.php:49，username 未净化进入 SQL 语句，source→sink 链静态闭合，可远程触发。
POC 备注：仅文本工件，不执行；TARGET 由授权测试人员手动替换。

### F-3: 058_06.php 登录认证查询 username/password 拼接 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_06.php:22-24`
- **来源**：`rule`

**描述**

攻击者通过 query 参数 `login_user`（058_06.php:20 读取，对应 username/password 字段）提交输入。058_06.php:22 直接拼接：`$sql = "SELECT * FROM users WHERE username='$username' and password='$password'";`，058_06.php:24 由 `mysql_query($sql)` 执行。未见转义或预处理，单引号闭合即可注入；058_06.php:24 的 die 分支回显固定文案，但布尔/时间盲注仍可行。

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

可绕过登录认证（`' OR '1'='1` 使查询恒真），或以 UNION/盲注方式读取 users 表口令等敏感数据，导致账户接管与数据泄露。

**CVE / CWE 论证**

CWE-89。外部可达：登录表单参数直接进入 SQL，无需认证；利用链闭合：058_06.php:20 login_user → 058_06.php:22 拼接 → 058_06.php:24 mysql_query，无净化。

**修复建议**

改用参数化查询绑定 username/password；口令比对使用 password_verify()；对输入做白名单与长度限制；统一错误处理，避免差异化响应辅助盲注。

**验证说明**

静态证据：入口 POST /058_06；source=query/login_user；sink=058_06.php:24；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 `username=admin'-- -` 或 `' OR '1'='1` → 058_06.php:20 读入 → 058_06.php:22 拼入 WHERE 条件 → 058_06.php:24 执行，返回任意用户记录或恒真结果，实现认证绕过。
PocWriter 建议（未采纳，缺少端点 /058_06）：针对 058_06.php:24 的 SQL 注入 POC。注入点为 POST 参数 login_user，源码将其直接拼接进登录查询。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_06）：符合 CWE-89。漏洞位于 058_06.php:24，login_user 未净化进入 SQL 语句，source→sink 链静态闭合，可远程触发。
POC 备注：仅文本工件，不执行；TARGET 由授权测试人员手动替换。

### F-4: 058_08.php 修改口令 UPDATE 语句 current_password 拼接 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_08.php:37-39`
- **来源**：`rule`

**描述**

攻击者通过 query 参数 `current_password`（058_08.php:32 读取，$pass/$username 同源）提交输入。058_08.php:38 直接拼接：`$sql = "UPDATE users SET PASSWORD='$pass' where username='$username' and password='$curr_pass' ";`，058_08.php:39 由 `mysql_query($sql)` 执行。无转义、无预处理，单引号闭合即可改变 WHERE 条件或追加语句。

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

可绕过当前口令校验直接改写任意用户（含管理员）口令，实现账户接管；也可通过报错/盲注读取数据库内容，属于越权与数据篡改。

**CVE / CWE 论证**

CWE-89。外部可达：改密接口由 HTTP query 驱动；利用链闭合：058_08.php:32 current_password → 058_08.php:38 拼接 → 058_08.php:39 mysql_query，无净化。

**修复建议**

使用预处理语句绑定 curr_pass/pass/username；改密前在服务端校验会话身份与旧口令（password_verify）；对输入做长度与字符白名单；移除 mysql_error() 回显。

**验证说明**

静态证据：入口 POST /058_08；source=query/current_password；sink=058_08.php:39；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 `current_password=' OR '1'='1` 并指定目标 username 与新 pass → 058_08.php:32 读入 → 058_08.php:38 拼入 UPDATE 的 WHERE → 058_08.php:39 执行，WHERE 恒真使任意用户口令被改写。
PocWriter 建议（未采纳，缺少端点 /058_08）：针对 058_08.php:39 的 SQL 注入 POC。注入点为 POST 参数 current_password，源码将其直接拼接进密码校验查询。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_08）：符合 CWE-89。漏洞位于 058_08.php:39，current_password 未净化进入 SQL 语句，source→sink 链静态闭合，可远程触发。
POC 备注：仅文本工件，不执行；TARGET 由授权测试人员手动替换。

### F-5: 058_08.php 密码修改页仅凭客户端可控 Cookie Auth 判定登录，可绕过认证直接改任意用户密码

- **类型**：`auth_bypass` / CWE-287
- **严重度**：`high`
- **置信度**：`0.72`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`058_08.php:7-14`
- **来源**：`llm_finding`

**描述**

058_08.php 的访问控制只检查 `isset($_COOKIE["Auth"])`（第7行），而该 Cookie 在 058_06.php 第44行由服务端以固定值 1 下发（`setcookie("Auth", 1, time()+3600)`），攻击者无需任何凭据即可自行构造 `Cookie: Auth=1` 通过校验。通过后第31行 `$username = $_SESSION["username"]` 取当前会话用户名，第38行拼接 `UPDATE users SET PASSWORD='$pass' where username='$username' and password='$curr_pass'`。由于 `$curr_pass` 来自用户输入且仅经 `mysql_real_escape_string`（第32行），无法阻止逻辑绕过；更关键的是认证门本身可被伪造 Cookie 绕过，攻击者只要持有目标用户名对应的会话（或结合 058_06.php 的登录逻辑）即可在无有效旧密码的情况下修改密码。根因是认证判定依赖客户端可写 Cookie 而非服务端会话。

**source / sink**

- source：cookie `Auth`（058_08.php）
- sink：058_08.php:14 058_08.php:38 mysql_query(UPDATE users SET PASSWORD=...)

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_08.php:7` | 仅判断 Cookie Auth 是否存在，存在即放行 | 攻击者自设 Cookie: Auth=1 | isset 只校验存在性，不校验签名/服务端状态 |
| 2 | `058_08.php:31` | 从会话取用户名作为 UPDATE 条件 | $username = $_SESSION["username"] |  |
| 3 | `058_08.php:38` | 拼接并执行 UPDATE 修改密码 | $pass/$curr_pass 经 mysql_real_escape_string 后拼入 SQL |  |

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

绕过登录校验，未授权修改账户密码，导致账户接管

**CVE / CWE 论证**

CWE-287/CWE-565：认证依赖客户端可控 Cookie，外部无需有效凭据即可通过门禁并触发密码更新

**修复建议**

移除对 Cookie Auth 的信任，仅以服务端 $_SESSION 判定登录态；改密前强制校验旧密码并绑定会话用户

**验证说明**

需确认 058_06.php 登录后 $_SESSION['username'] 的赋值路径及会话是否可预测/固定；若无法获得目标用户会话，则仅能改自身密码，影响降级
模型 POC 要点：伪造 Auth Cookie 进入改密页并提交改密请求
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /058_08.php）：针对 058_08.php:14 的认证绕过 POC。源码依据 Cookie Auth 的值判断身份，攻击者可伪造 Cookie 值绕过认证。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_08.php）：符合 CWE-287。漏洞位于 058_08.php:14，认证仅依赖客户端可控 Cookie 值，可远程触发。
POC 备注：仅文本工件，不执行；TARGET 由授权测试人员手动替换。Cookie 值 admin 需与源码判断逻辑一致，若源码使用其他比较值需按源码调整。

### F-6: 058_06.php 认证 Cookie 使用固定值 Auth=1（CWE-330/CWE-565）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_06.php:43-44`
- **来源**：`rule`

**描述**

058_06.php:44 在登录成功后执行 `setcookie("Auth", 1, time()+3600);`，认证标志为常量 1，不含任何随机性或与用户绑定的不可预测值；058_06.php:43 仅把用户名写入 $_SESSION。攻击者无需猜测随机数，只需在请求中携带 `Auth=1` 即可伪造“已认证”标志（是否被服务端接受取决于其他文件的校验逻辑，片段未覆盖）。

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
curl -sS -i -X POST 'http://TARGET:8080/058_06' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：返回 dvwaSession 等会话 Cookie，记录其值

3. **保持同一会话再次 POST，并比较两次会话 Cookie**

```http
curl -sS -i -X POST 'http://TARGET:8080/058_06' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：Cookie 值出现 1、2、3 等递增/可预测序列，或可重放访问

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-381e6544791c`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若下游页面仅以 Auth Cookie 判断登录态，攻击者可伪造该 Cookie 绕过认证，访问受保护功能，导致越权与账户冒用。

**CVE / CWE 论证**

CWE-330（使用不充分的随机值）/CWE-565（依赖不可信 Cookie 做安全决策）。属配置/实现型弱点，无 HTTP 污点链要求；证据为 058_06.php:44 的常量 Cookie 值。外部可达性取决于下游校验，片段未覆盖，故置信度较低。

**修复建议**

认证状态完全依赖服务端会话（session_regenerate_id 后使用随机 session id），不要用常量 Cookie 表示登录态；Cookie 设置 HttpOnly、Secure、SameSite；登录后轮换会话标识。

**验证说明**

静态证据：入口 POST /058_06；source=session/dvwaSession；sink=058_06.php:44；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者直接构造请求头 `Cookie: Auth=1` → 下游受保护页面若仅检查该 Cookie 即视为已登录 → 未认证访问受保护资源。
PocWriter 建议（未采纳，缺少端点 /058_06）：针对 058_06.php:44 的弱会话 ID POC。源码生成的 dvwaSession Cookie 值可预测（如递增序列），攻击者可枚举或重放会话。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_06）：符合 CWE-330。漏洞位于 058_06.php:44，会话标识生成使用可预测序列，可远程触发。
POC 备注：仅文本工件，不执行；TARGET 由授权测试人员手动替换。<第一次值>/<预测值> 需按实际响应填写，不可使用抽象占位符提交。

### F-7: 058_08.php 登出使用固定值 Auth=1 的 Cookie 语义（CWE-330/CWE-565）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_08.php:65-66`
- **来源**：`rule`

**描述**

058_08.php:65 调用 session_destroy()，058_08.php:66 执行 `setcookie('Auth', 1 , time()-3600);` 以过期方式清除 Cookie。该 Cookie 的值恒为常量 1，说明认证标志本身不含随机性、不与用户绑定；攻击者可直接构造 `Auth=1` 伪造登录态（是否被接受取决于其他文件的校验，片段未覆盖）。

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
curl -sS -i -X POST 'http://TARGET:8080/058_08' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：返回 dvwaSession 等会话 Cookie，记录其值

3. **保持同一会话再次 POST，并比较两次会话 Cookie**

```http
curl -sS -i -X POST 'http://TARGET:8080/058_08' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：Cookie 值出现 1、2、3 等递增/可预测序列，或可重放访问

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-84e9d7c625f8`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若下游以该 Cookie 判定登录态，可被伪造以绕过认证、冒用身份访问受保护功能；同时常量值使会话固定/伪造成本极低。

**CVE / CWE 论证**

CWE-330/CWE-565。配置/实现型弱点，证据为 058_08.php:66 的常量 Cookie 值；外部可达性依赖下游校验逻辑，片段未覆盖，置信度较低。

**修复建议**

认证状态仅依赖服务端随机会话标识；登出时同时失效服务端会话并清除 Cookie；Cookie 加 HttpOnly/Secure/SameSite；避免以常量标志表示认证。

**验证说明**

静态证据：入口 POST /058_08；source=session/dvwaSession；sink=058_08.php:66；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 `Cookie: Auth=1` → 下游页面若仅检查该 Cookie 即放行 → 未认证访问受保护资源。

### F-8: 058_04.php 直接回显 $_SESSION['username'] 未编码，可存储型 XSS

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`058_04.php:25-27`
- **来源**：`llm_finding`

**描述**

058_04.php 第26行 `echo $_SESSION["username"];` 将会话用户名直接输出到 HTML，无 htmlspecialchars 编码。用户名在 058_05.php 注册时由用户可控（第25行仅做 SQL 转义，未做 HTML 编码），存入 users 表后经 058_06.php 登录写入 $_SESSION['username']（第43行），最终在 058_04.php 回显。构成存储型 XSS：注册含脚本的用户名，登录后触发。

**source / sink**

- source：session `username`（058_04.php）
- sink：058_04.php:27 058_04.php:26 echo

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_05.php:25` | 注册时 username 仅 SQL 转义未 HTML 编码 | 原始脚本字符串入库 |  |
| 2 | `058_06.php:43` | 登录成功写入会话 | $_SESSION['username'] = $login |  |
| 3 | `058_04.php:26` | 直接 echo 到页面 | 脚本在浏览器执行 |  |

**POC**

针对 /058_04.php（GET）的 跨站脚本 POC。注入点：GET 参数 username；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/058_04.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/058_04.php?username=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-a8e9805999ee`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

存储型 XSS，可窃取会话或执行敏感操作

**CVE / CWE 论证**

CWE-79：用户可控数据未编码输出到 HTML

**修复建议**

输出时使用 htmlspecialchars 编码

**验证说明**

需确认 058_05.php 注册是否允许特殊字符用户名（无长度/字符白名单）
模型 POC 要点：注册恶意用户名后登录访问 058_04.php
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /058_04.php）：针对 058_04.php:27 的反射型 XSS POC。注入点为 GET 参数 username，源码将其未编码输出到页面。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_04.php）：符合 CWE-79。漏洞位于 058_04.php:27，username 未编码输出到 HTML，source→sink 链静态闭合，可远程触发。
POC 备注：仅文本工件，不执行；TARGET 由授权测试人员手动替换。注意：输入标注 source 为 session username，若实际为会话存储值，需先通过设置会话的入口写入该值再访问本页，此处按 GET 参数回显路径给出 POC，若源码确认为会话读取则需补充写入步骤。

### F-9: 058_08.php 改密操作缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.56`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_08.php:37-38`
- **来源**：`rule`

**描述**

058_08.php:37-38 的改密逻辑在收到 `Change` 请求后直接执行 `UPDATE users SET PASSWORD=...`，代码片段中未见 CSRF token 校验、Origin/Referer 校验或二次口令确认。攻击者可构造第三方页面自动向该端点提交表单，借受害者已登录会话完成改密。注意：片段未展示会话校验代码，认证前提需结合完整文件复核。

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

在受害者已登录且浏览器携带会话的情况下，攻击者可将其口令改为攻击者已知值，从而接管账户；若目标为管理员则导致后台失陷。

**CVE / CWE 论证**

CWE-352。外部可达：改密端点可被跨站表单触发；利用链依赖受害者已认证会话（片段未给出会话校验，属证据缺口），故置信度中等。

**修复建议**

为改密表单引入一次性 CSRF token 并在服务端校验；校验 Origin/Referer；会话 Cookie 设置 SameSite=Lax/Strict；改密要求重新输入旧口令。

**验证说明**

静态证据：入口 GET /058_08；source=query/Change；sink=058_08.php:38；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者诱导已登录受害者访问恶意页面 → 页面自动 POST 到 058_08.php 的改密端点（携带 Change 与新的 pass/username）→ 058_08.php:38 执行 UPDATE → 受害者口令被替换。
PocWriter 建议（未采纳，缺少端点 /058_08）：针对 058_08.php:38 的 CSRF POC。密码修改接口接受 GET 请求且无 CSRF token 校验，攻击者可诱导已登录用户触发密码变更。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /058_08）：符合 CWE-352。漏洞位于 058_08.php:38，密码修改接口无 CSRF 防护且接受 GET，可远程触发。
POC 备注：仅文本工件，不执行；TARGET 由授权测试人员手动替换。步骤 2 中 <受害者会话> 需替换为实际会话 Cookie 值，不可使用抽象占位符提交。

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
| `xss` | CWE-79 | 是 | 1 |
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
| safety_guard | 安全防护 | 3.59 | 是 |
| surface_mapper | 攻击面测绘 | 14.01 | 是 |
| deep_finder | LLM 深挖 | 19.22 | 是 |
| candidate_screener | 候选筛选 | 9.58 | 是 |
| vulnerability_analyzer | 漏洞分析 | 17.65 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 22.24 | 是 |
| coordinator | 管线协调 | 7.7 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
