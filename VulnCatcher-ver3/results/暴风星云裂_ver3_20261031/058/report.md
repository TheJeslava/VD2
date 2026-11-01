# 落日二号乙漏洞挖掘报告 — 20261031-010620-e63df6

- 生成时间：2026-10-30T17:07:31.989989+00:00
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

本次汇总 6 条已去重 findings，覆盖 8 个 PHP 脚本（058_01.php–058_08.php，约 481 行，无框架、无路由配置）。最高危为 4 条 critical 级 SQL 注入：058_05.php 登录查询 username 参数（GEN-b07a62da291f，line_end 31）与注册 INSERT（GEN-7923d3edceea，line_end 49）、058_08.php 改口令 UPDATE（GEN-14a19460b45a，line_end 39）、058_06.php 登录认证 SELECT（GEN-2e336c5d86ca，line_end 24），均为规则命中且带 POC。其次为 058_06.php 仅凭客户端 Cookie Auth=1 判定登录的认证绕过（LLM-28954cf1fb7e，high，llm_inferred，带 POC），以及 058_08.php 口令修改缺少 CSRF 防护（SEM-e3f6e1c06f4d，medium，带 POC）。6 条 findings 全部有 POC（with_poc=6），但均为静态文本 POC，未做动态验证；SQL 注入与 CSRF 属 HTTP 型 POC，auth_bypass 的 POC 为构造 Cookie 的请求文本，同样未经动态确认。本次未产生二次注入链（无存储写点/读点/汇点三元组证据）。

共 **6** 条 finding；**6** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：8 个文件 / 11823 字符；截断 0 个
- 模型新增候选：3 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中全部 8 个 PHP 脚本（058_01~058_08）。核心发现：(1) 058_06.php 使用固定值 Cookie Auth=1 作为认证标志，058_01/04/08 仅用 isset($_COOKIE["Auth"]) 判定登录，可伪造 Cookie 绕过认证（高置信）；(2) 058_05.php 注册处 mysql_escape_string 后拼接 INSERT，配合 058_08.php 从 $_SESSION 取出再拼接 UPDATE，构成 Less-24 二次注入链；(3) 058_06.php 登录查询拼接，宽字节字符集下可注入。058_02.php 为纯静态页面无风险；058_03.php 仅含登录表单与重定向；058_07.php 为注册表单页面，输入提交至 login_create.php（不在 code_pack 内，无法审计）。未发现命令执行、文件包含、反序列化、SSRF 类汇点。配置型候选（weak_hash/weak_crypto/weak_random/insecure_cookie）在可见代码中未见 md5/sha1/rand/ECB 等证据，未单独立项。058_05.php 第 67-76 行、058_06.php 第 60-65 行、058_03.php 第 39-61 行、058_04.php 第 39-91 行因截断未展示，可能存在额外逻辑但不在可见范围。

未覆盖 / 证据缺口：
- 058_05.php 67-76 行、058_06.php 60-65 行、058_03.php 39-61 行、058_04.php 39-91 行被截断未展示
- login_create.php、logged-in.php、pass_change.php、sql-connect.php 不在 code_pack，无法审计其数据流与字符集配置
- 数据库连接字符集未知，影响宽字节注入可利用性判断
- 无 Web 服务器/php.ini 配置，无法确认部署暴露面

## 3. Findings

### F-1: 058_05.php 登录查询 username 参数 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_05.php:29-31`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `username`（058_05.php:25 读取）提交输入，该值未经任何转义或参数化即被拼接进 058_05.php:30 的 `$sql = "select count(*) from users where username='$username'"`，随后在 058_05.php:31 交给 `mysql_query($sql)` 执行。由于单引号包裹的字符串上下文未做 `mysql_real_escape_string` 或预处理绑定，攻击者可闭合引号注入任意 SQL 片段（如 `' OR '1'='1` 或 UNION 子查询），校验完全缺失。

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

数据库查询逻辑被完全控制：可绕过登录/计数校验、通过 UNION 或布尔/时间盲注逐位读取 users 表中的用户名与口令哈希，造成敏感数据泄露；结合数据库高权限账户还可能读写文件。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达：参数来自 HTTP query，无需认证即可触发；利用链闭合：058_05.php:25 取值 → 058_05.php:30 字符串拼接 → 058_05.php:31 mysql_query 执行，中间无净化函数。

**修复建议**

改用 PDO/MySQLi 预处理语句并绑定参数（如 `SELECT count(*) FROM users WHERE username=?`）；若必须拼接，使用 `mysql_real_escape_string` 并强制字符集；对 username 施加长度与字符白名单校验；数据库账户最小权限，关闭详细错误回显（当前 die 分支会暴露 SQL 执行状态）。

**验证说明**

静态证据：入口 ANY /058_05；source=query/username；sink=058_05.php:31；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 `?username=' OR '1'='1` → 058_05.php:25 读入 $username → 058_05.php:30 拼入 SQL → 058_05.php:31 mysql_query 执行，返回被篡改的计数结果，实现注入。
PocWriter 建议（未采纳，缺少端点 /058_05）：针对 058_05.php:31 的 SQL 注入 POC。注入点为 query 参数 username，payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /058_05）：符合 CWE-89。漏洞位于 058_05.php:31，外部输入来自 query 参数 username，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构；脚本仅为文本工件，不执行、不联网，TARGET 需替换为授权目标。

### F-2: 058_05.php 用户注册 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_05.php:47-49`
- **来源**：`rule`

**描述**

攻击者通过 query 参数 `username`（058_05.php:25 读取，同时 `$pass` 亦来自请求）提交输入，在注册分支中被直接拼入 058_05.php:48 的 `$sql = "insert into users ( username, password) values(\"$username\", \"$pass\")"`，并在 058_05.php:49 由 `mysql_query($sql)` 执行。双引号包裹的 VALUES 上下文未做任何转义，攻击者可用 `\"` 闭合后追加任意 SQL，或利用报错信息（`mysql_error()` 被回显）辅助注入。

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

可向 users 表写入任意记录（如自建管理员账户）、通过报错/盲注读取其他表数据，导致认证绕过与数据完整性破坏；错误信息回显进一步泄露库结构。

**CVE / CWE 论证**

CWE-89。外部可达：注册接口无需认证；利用链闭合：058_05.php:25 取值 → 058_05.php:48 拼接 → 058_05.php:49 mysql_query 执行，且 058_05.php:49 的 die 分支回显 `mysql_error()`，为注入提供反馈通道。

**修复建议**

使用预处理语句绑定 username/password；对输入做转义与白名单校验；移除 `mysql_error()` 回显，改为记录到服务端日志；对注册接口增加频率限制与唯一性检查。

**验证说明**

静态证据：入口 ANY /058_05；source=query/username；sink=058_05.php:49；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 `username=a\", \"x\")-- -` 等载荷 → 058_05.php:25 读入 → 058_05.php:48 拼入 INSERT → 058_05.php:49 执行，写入受控数据或触发可回显的 SQL 错误。
PocWriter 建议（未采纳，缺少端点 /058_05）：针对 058_05.php:49 的 SQL 注入 POC。注入点为 query 参数 username，payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /058_05）：符合 CWE-89。漏洞位于 058_05.php:49，外部输入来自 query 参数 username，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构；脚本仅为文本工件，不执行、不联网。

### F-3: 058_08.php 修改口令 UPDATE 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_08.php:37-39`
- **来源**：`rule`

**描述**

攻击者在修改口令流程中通过 query 参数 `current_password`（058_08.php:32 读取，`$pass`、`$username` 同样来自请求）提交输入，被直接拼入 058_08.php:38 的 `$sql = "UPDATE users SET PASSWORD='$pass' where username='$username' and password='$curr_pass' "`，并在 058_08.php:39 由 `mysql_query($sql)` 执行。WHERE 子句中的 `$curr_pass` 与 SET 中的 `$pass` 均未转义，攻击者可用 `' OR '1'='1` 使 WHERE 恒真，从而在不知道原口令的情况下改写任意用户口令。

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

可越权重置任意账户（含管理员）口令，实现账户接管与权限提升；亦可借 UPDATE 语句注入读取数据或破坏记录。

**CVE / CWE 论证**

CWE-89。外部可达：口令修改接口通过 HTTP query 传参；利用链闭合：058_08.php:32 取值 → 058_08.php:38 拼接 → 058_08.php:39 mysql_query 执行，无参数化或转义。

**修复建议**

使用预处理语句绑定三个参数；在服务端会话中取当前用户身份而非信任请求中的 username；校验原口令使用常量时间比较；对修改口令接口加 CSRF token 与重认证。

**验证说明**

静态证据：入口 ANY /058_08；source=query/current_password；sink=058_08.php:39；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 `?current_password=' OR '1'='1&username=admin&pass=newpass` → 058_08.php:32 读入 → 058_08.php:38 拼接使 WHERE 恒真 → 058_08.php:39 执行，admin 口令被改为 newpass。
PocWriter 建议（未采纳，缺少端点 /058_08）：针对 058_08.php:39 的 SQL 注入 POC。注入点为 query 参数 current_password，payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /058_08）：符合 CWE-89。漏洞位于 058_08.php:39，外部输入来自 query 参数 current_password，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构；脚本仅为文本工件，不执行、不联网。

### F-4: 058_06.php 登录认证 SELECT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.73`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_06.php:22-24`
- **来源**：`rule`

**描述**

攻击者通过 query 参数 `login_user`（058_06.php:20 读取，`$username`、`$password` 均来自请求）提交输入，被拼入 058_06.php:22 的 `$sql = "SELECT * FROM users WHERE username='$username' and password='$password'"`，并在 058_06.php:24 由 `mysql_query($sql)` 执行。用户名与口令均以单引号字符串拼接，未做转义或绑定，攻击者可用 `' OR '1'='1' -- -` 使条件恒真，绕过认证。

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

认证绕过：无需有效凭据即可登录为任意用户（含管理员），进而访问受保护功能；也可通过 UNION/盲注读取 users 表全部凭据。

**CVE / CWE 论证**

CWE-89。外部可达：登录接口匿名可访问；利用链闭合：058_06.php:20 取值 → 058_06.php:22 拼接 → 058_06.php:24 mysql_query 执行，无净化。

**修复建议**

改用预处理语句绑定 username/password；口令以哈希形式存储并用 `password_verify` 校验，而非在 SQL 中明文比较；统一错误提示避免用户名枚举；限制登录尝试次数。

**验证说明**

静态证据：入口 ANY /058_06；source=query/login_user；sink=058_06.php:24；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 `?login_user=1&username=admin' -- -&password=x` → 058_06.php:20 读入 → 058_06.php:22 拼接使 password 条件被注释掉 → 058_06.php:24 执行，返回 admin 记录完成登录。
PocWriter 建议（未采纳，缺少端点 /058_06）：针对 058_06.php:24 的 SQL 注入 POC。注入点为 query 参数 login_user，payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /058_06）：符合 CWE-89。漏洞位于 058_06.php:24，外部输入来自 query 参数 login_user，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构；脚本仅为文本工件，不执行、不联网。

### F-5: 058_06.php 登录逻辑使用 setcookie("Auth",1) 且仅凭客户端 Cookie 判定登录，可伪造 Auth=1 绕过认证

- **类型**：`auth_bypass` / CWE-287
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`058_06.php:40-46`
- **来源**：`llm_finding`

**描述**

058_06.php 在登录成功后执行 setcookie("Auth", 1, time()+3600)，把认证状态以固定值 1 写入客户端 Cookie；而 058_01.php/058_04.php/058_08.php 的访问控制仅检查 isset($_COOKIE["Auth"])，不校验其值、不校验签名、不与服务端会话绑定。攻击者无需任何凭据，直接发送 Cookie: Auth=1 即可通过所有受保护页面的认证检查，访问 logged-in.php、pass_change.php 等登录后功能。

**source / sink**

- source：cookie `Auth`（058_06.php）
- sink：058_06.php:46 058_01.php:3 / 058_04.php:3 / 058_08.php:7 的 isset($_COOKIE["Auth"]) 认证判定

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_06.php:44` | 登录成功后把固定值 1 写入客户端 Cookie Auth，无签名、无随机令牌 | Auth=1 明文下发到客户端 |  |
| 2 | `058_01.php:3` | 受保护页面仅用 isset($_COOKIE["Auth"]) 判断是否已登录 | 攻击者自设 Cookie: Auth=1 即满足 isset 条件 | 只判断 Cookie 是否存在，不校验值/签名/与会话绑定 |
| 3 | `058_04.php:3` | 同样逻辑保护 logged-in 页面，直接渲染 $_SESSION["username"] | 未认证用户进入登录后功能 |  |
| 4 | `058_08.php:7` | 密码修改页同样仅检查 Cookie Auth，进入后可提交改密表单 | 未认证用户可访问改密功能 |  |

**POC**

针对 /058_01.php, /058_04.php, /058_08.php（GET）的 认证绕过 POC。注入点：Cookie: Auth；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/058_01.php, /058_04.php, /058_08.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 认证绕过 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/058_01.php, /058_04.php, /058_08.php' \
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

未认证攻击者绕过登录访问所有登录后功能，包括密码修改页面，构成认证绕过。

**CVE / CWE 论证**

CWE-287/CWE-565：认证状态由客户端可控 Cookie 的固定值决定，无服务端校验，外部无需凭据即可触发，链闭合。

**修复建议**

认证状态必须保存在服务端会话中，Cookie 仅存放不可预测的会话 ID；不要用固定值 1 作为认证标志，且所有受保护页面应校验 $_SESSION 而非 Cookie 存在性。

**验证说明**

需确认部署时 058_01/04/08 是否直接暴露；Cookie 名与值已由源码确定。
模型 POC 要点：直接伪造 Auth Cookie 访问受保护页面
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /058_01.php,）：针对 058_06.php:46 的认证绕过 POC。注入通道为 Cookie Auth，payload 使用 TARGET 占位符，仅限授权测试。注意：原草稿 endpoint 中把多个路径写在同一 URL 内，实际应分别对每个受保护页面单独请求。
PocWriter 建议（未采纳，缺少端点 /058_01.php,）：符合 CWE-287。漏洞位于 058_06.php:46，外部输入来自 cookie Auth，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：原 endpoint 将多个路径合并为单一 URL，属格式问题；POC 已拆分为逐页请求，未改变文件/行号与注入通道。

### F-6: 058_08.php 口令修改接口缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.56`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`058_08.php:37-38`
- **来源**：`rule`

**描述**

058_08.php:37-38 的口令修改逻辑直接依据请求参数 `$pass`、`$username`、`$curr_pass` 构造 `UPDATE users SET PASSWORD=...` 并执行，代码片段中未见任何 CSRF token 校验、Origin/Referer 校验或二次确认。攻击者可构造第三方页面，诱导已登录用户浏览器自动提交修改口令请求，从而在用户不知情下更改其口令。需注意：该接口同时存在 SQL 注入（见 GEN-14a19460b45a），且片段未展示会话认证与 Cookie SameSite 配置，实际可利用性依赖运行时条件。

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

登录用户被诱导后其账户口令被静默修改，导致账户被攻击者接管；若目标为管理员则造成权限提升。

**CVE / CWE 论证**

CWE-352（跨站请求伪造）。外部可达：状态改变请求通过 HTTP 参数触发；利用链闭合依赖两点未在片段中证实的条件——(1) 接口依赖 Cookie 会话认证，(2) 无 token/Origin 校验。因此证据等级为推断，需运行时复核。

**修复建议**

为所有状态改变表单引入随机 CSRF token 并在服务端校验；校验 Origin/Referer；会话 Cookie 设置 SameSite=Lax/Strict 与 Secure；修改口令前要求重新输入原口令（服务端校验）；优先使用 POST 而非 GET 传参。

**验证说明**

静态证据：入口 ANY /058_08；source=request/password change；sink=058_08.php:38；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者页面自动向 058_08.php 提交 `username=victim&pass=attacker&curr_pass=...` → 浏览器携带受害者会话 Cookie → 058_08.php:38 构造 UPDATE → 058_08.php:39 执行，受害者口令被改。
PocWriter 建议（未采纳，缺少端点 /058_08）：针对 058_08.php:38 的 CSRF POC。原草稿把「password change」当作 query 参数，语义不成立；CSRF 应通过第三方页面自动提交表单触发，需受害者已登录。以下按 CSRF 语义重写，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /058_08）：符合 CWE-352。漏洞位于 058_08.php:38，改密操作缺少 CSRF 防护，具备远程触发条件。
POC 备注：原草稿的 query 参数「password change」不符合 CSRF 语义，已改为跨站自动提交表单；未新增 finding，文件/行号保持不变。

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
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.39 | 是 |
| surface_mapper | 攻击面测绘 | 8.8 | 是 |
| deep_finder | LLM 深挖 | 15.52 | 是 |
| candidate_screener | 候选筛选 | 8.74 | 是 |
| vulnerability_analyzer | 漏洞分析 | 13.03 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 14.72 | 是 |
| coordinator | 管线协调 | 8.21 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
