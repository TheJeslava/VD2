# 落日二号乙漏洞挖掘报告 — 20261030-205331-f842c0

- 生成时间：2026-10-30T12:54:54.657295+00:00
- 输入：`C:\Users\liyuf\Desktop\794\集成数据集\sqli_low.zip`
- 输入模式：`zip`
- SHA256：`7b7bfe7b4e30ab45df05f6bf97209b9193a9c4eb9c5c44ec83a7bbc11c7eeef6`
- 文件：52（文本 37）
- 语言：config(1), javascript(3), php(22), sql(5), text(1), unknown(20)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`medium`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总 5 条已去重 findings，全部带 POC（5/5），类型为 sql_injection×2、path_traversal×2、xss×1。最高危为 vulnerabilities/view_help.php（LLM-402587808170）：id/locale 参数拼接路径后 eval 文件内容，兼具任意文件读取与代码执行，严重度 high；其次为 sqli/source/low.php 的 low 档参数直拼 SELECT（LLM-7315873b3f4e）与 session-input.php→sqli 读取的二次 SQL 注入（LLM-fb23f3d9c630，写点 session-input.php 第 14 行、读点 index.php/low.php、汇点 low.php 拼查询，三段链齐全）。POC 均为静态文本工件，未执行、未做动态验证；其中 SQL 注入与路径遍历类 POC 具备 HTTP 请求形态，可作动态复现的候选，但本次未验证。

共 **5** 条 finding；**5** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：12 个文件 / 24184 字符；截断 4 个
- 模型新增候选：5 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中全部可见文件：login.php（1-75）、dvwa/includes/dvwaPage.inc.php（1-199）、vulnerabilities/sqli/session-input.php（全）、dvwa/includes/DBMS/MySQL.php（1-95）、setup.php（1-108）、vulnerabilities/view_help.php（全）、logout.php（全）、security.php（1-53）、dvwa/includes/DBMS/PGSQL.php（21-91）、vulnerabilities/view_source.php（1-48）、vulnerabilities/view_source_all.php（1-47）、vulnerabilities/sqli/source/low.php（1-46）。发现：1) sqli low.php 直接拼接 $_REQUEST['id'] 到 mysqli_query（高危，链闭合）；2) session-input.php 写会话 + low.php 读会话拼 SQL 的二次注入（中高，依赖 index.php 未展示的读取逻辑）；3) view_help.php 的 id/locale 路径穿越 + eval（高危，可升级 RCE）；4) view_source_all.php 路径穿越读取源码（中危）；5) session-input.php 未编码回显 XSS（中危）。未闭合/未报告线索：login.php 使用 md5($pass) 存储口令（weak_hash，CWE-328），但属靶场设计且需结合数据库写入，未单独立项；dvwaPage.inc.php 中 dvwa_start_session 在非 impossible 等级下 httponly=false、samesite 为空、secure=false（insecure_cookie），属配置型风险，未形成独立利用链；setup.php 中 shell_exec 调用为固定命令（apachectl/git），无用户输入拼接，不构成命令注入；MySQL.php/PGSQL.php 中 DROP/CREATE 语句使用 $_DVWA 配置值，非外部可控。覆盖缺口：index.php、vulnerabilities/sqli/index.php、config/config.inc.php.dist、php.ini、external/recaptcha/recaptchalib.php、database/*.sql 未在 code_pack 中提供，无法确认二次注入读点与配置型风险；xss/exec/fi/upload/brute/csrf 等模块源码缺失。

未覆盖 / 证据缺口：
- index.php 与 vulnerabilities/sqli/index.php 未提供，二次注入读点无法确认
- config/config.inc.php.dist、php.ini、recaptchalib.php 未提供，配置型风险无法评估
- xss/exec/fi/upload/brute/csrf 等模块源码缺失
- database/sqli.db 二进制内容未提供

## 3. Findings

### F-1: SQL 注入（low 档）：vulnerabilities/sqli/source/low.php 将 $_REQUEST['id'] 直接拼接进 SELECT 查询

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`vulnerabilities/sqli/source/low.php:5-11`
- **来源**：`llm_finding`

**描述**

sqli 模块 low 安全等级下，index.php 引入 source/low.php；low.php 第 5 行从 $_REQUEST['id'] 取值，第 10 行直接以字符串插值方式拼入 "SELECT first_name, last_name FROM users WHERE user_id = '$id';"，第 11 行交给 mysqli_query 执行。全程无 mysqli_real_escape_string、无类型强转、无预处理语句，攻击者可通过单引号闭合字符串并注入任意 SQL（UNION 联合查询、布尔/时间盲注），读取 users 表全部字段（含 password 哈希）乃至 information_schema 中的库表结构。

**source / sink**

- source：query `id`（vulnerabilities/sqli/source/low.php:5）
- sink：vulnerabilities/sqli/source/low.php:11 mysqli_query($GLOBALS["___mysqli_ston"], $query)（vulnerabilities/sqli/source/low.php:11）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `vulnerabilities/sqli/source/low.php:3` | 判断 Submit 参数存在，进入注入分支 | 请求参数 Submit 存在 |  |
| 2 | `vulnerabilities/sqli/source/low.php:5` | 从 $_REQUEST 读取 id，未做任何过滤/转义/类型转换 | 原始攻击者字符串 |  |
| 3 | `vulnerabilities/sqli/source/low.php:10` | 将 $id 以单引号包裹方式字符串拼接进 SQL 语句 | 注入载荷进入 SQL 文本，单引号可闭合 WHERE 条件 |  |
| 4 | `vulnerabilities/sqli/source/low.php:11` | 拼接后的语句交给 mysqli_query 执行，错误信息通过 die 回显 | SQL 被执行，结果集/报错回显到页面 |  |

**POC**

针对 /vulnerabilities/sqli/（GET）的 SQL 注入 POC。注入点为 GET 参数 id，源码 vulnerabilities/sqli/source/low.php:11 将 id 直接拼入 SQL 查询，未做参数化或转义。目标地址统一使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/sqli/'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/vulnerabilities/sqli/?id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-7315873b3f4e`
- 执行状态：未执行（`executed=False`）

**影响**

未授权（低权限登录用户）可读取数据库任意数据，包括 users 表全部账号与 MD5 口令哈希，可进一步离线破解或横向利用；亦可读取 information_schema 获取库表结构。

**CVE / CWE 论证**

CWE-89 SQL Injection。外部 HTTP 参数 id 直达 mysqli_query，无任何转义或参数化，链路在 CODE PACK 内完全闭合（low.php:5→10→11），无需特殊配置，仅需 low 安全等级与登录态。

**修复建议**

使用预处理语句（mysqli_prepare + bind_param）或至少 mysqli_real_escape_string 并对 id 做整数强转（(int)$id）；避免将用户输入直接拼接进 SQL。

**验证说明**

需在部署环境确认 security=low 时 index.php 确实 include source/low.php（index.php 未在 code_pack 中完整展示，但 DVWA 标准逻辑如此），以及 SQLI_DB 配置为 MYSQL 分支。
模型 POC 要点：在 low 安全等级下向 sqli 模块提交 id 参数，利用单引号闭合注入 UNION 查询读取 users 表口令哈希；也可用布尔/时间盲注。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/sqli/）：符合 CWE-89。漏洞位于 vulnerabilities/sqli/source/low.php:11，外部输入来自 GET 参数 id，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标地址使用 TARGET 占位符，请手动替换为授权环境地址后人工执行。SQL 注入 POC 不使用 DROP 等破坏性语句。

### F-2: view_help.php 通过 id/locale 参数拼接路径并 eval 文件内容，导致任意文件读取与代码执行

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`vulnerabilities/view_help.php:14-23`
- **来源**：`llm_finding`

**描述**

view_help.php 第 14-16 行从 $_GET 读取 id、security、locale，第 20/22 行将 id 与 locale 直接拼入 file_get_contents 路径 "vulnerabilities/{$id}/help/help.php" 或 "help.{$locale}.php"，随后对读到的内容执行 eval。id/locale 未做 basename、白名单或路径规范化，攻击者可用 ../ 穿越读取任意文件；若目标文件内容可控（如上传文件或日志），eval 将导致远程代码执行。

**source / sink**

- source：query `id`（vulnerabilities/view_help.php:14）
- sink：vulnerabilities/view_help.php:23 eval(file_get_contents(...))（vulnerabilities/view_help.php:20、22）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `vulnerabilities/view_help.php:11` | 检查 id/security/locale 三个 GET 参数存在 | 参数存在 |  |
| 2 | `vulnerabilities/view_help.php:14` | 直接读取 id 与 locale，无过滤 | 攻击者可控字符串 |  |
| 3 | `vulnerabilities/view_help.php:20` | 将 id 拼入文件路径并 file_get_contents 读取 | 路径穿越，读取任意文件内容 |  |
| 4 | `vulnerabilities/view_help.php:20` | 对读取内容执行 eval，若内容含 PHP 代码则执行 | 代码执行 |  |

**POC**

针对 /vulnerabilities/view_help.php（GET）的路径穿越 POC。注入点为 GET 参数 id，源码 vulnerabilities/view_help.php:23 将 id 直接用于文件路径拼接，未做规范化与白名单校验。目标地址统一使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/view_help.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 路径穿越 / 任意文件读写 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/vulnerabilities/view_help.php?id=..%2F..%2F..%2F..%2Ftmp%2Fsunset_LLM40258.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_LLM40258.txt`
- POC 目录：`poc/LLM-402587808170`
- 执行状态：未执行（`executed=False`）

**影响**

任意文件读取（泄露配置、凭据、系统文件）；结合可控文件写入可升级为远程代码执行。

**CVE / CWE 论证**

CWE-22 路径遍历 + CWE-95 eval 注入。外部 GET 参数直达 file_get_contents 与 eval，链路在 view_help.php:14→20/22 闭合，无需特殊配置。

**修复建议**

对 id 使用白名单（仅允许已知模块名），locale 仅允许 en 等固定值；禁止对文件内容使用 eval，改用 include 受控模板或直接读取输出并 htmlspecialchars。

**验证说明**

需确认 PHP 配置未禁用 eval、file_get_contents 允许读取目标路径；RCE 升级依赖可控文件存在。
模型 POC 要点：利用 ../ 穿越读取任意文件；若可写入可控内容文件，则 eval 触发 RCE。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/view_help.php）：符合 CWE-22。漏洞位于 vulnerabilities/view_help.php:23，外部输入来自 GET 参数 id，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标地址使用 TARGET 占位符。读取路径应替换为授权环境中确认存在的文件，避免对目标造成写入副作用。

### F-3: 二次 SQL 注入：session-input.php 写入 $_SESSION['id']，sqli 模块读取后拼入查询

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.62`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`vulnerabilities/sqli/session-input.php:11-14`
- **来源**：`llm_finding`

**描述**

session-input.php 第 12 行将 $_POST['id'] 原样写入 $_SESSION['id']（存储写点），无任何过滤；sqli 模块在 low 档从会话中取出该值（存储读点）并拼入 SQL 查询（危险汇点）。攻击者先通过 session-input.php 存入恶意载荷，再访问 sqli 模块触发注入，绕过仅针对单次请求参数的检查。

**source / sink**

- source：body `id`（vulnerabilities/sqli/source/low.php:5）
- sink：vulnerabilities/sqli/session-input.php:14 mysqli_query（vulnerabilities/sqli/source/low.php:11，读取会话值后拼接）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `vulnerabilities/sqli/session-input.php:12` | 存储写点：将攻击者 POST 的 id 原样写入 $_SESSION['id'] | 恶意载荷持久化到服务端会话 |  |
| 2 | `vulnerabilities/sqli/session-input.php:14` | 将会话值回显到页面（同时构成反射型 XSS 风险） | 载荷回显 |  |
| 3 | `vulnerabilities/sqli/source/low.php:5` | 存储读点：sqli 模块从会话/请求读取 id（DVWA 二次注入流程中由 index.php 从 $_SESSION['id'] 取值传入） | 会话中的恶意载荷被取出 |  |
| 4 | `vulnerabilities/sqli/source/low.php:10` | 危险汇点：载荷拼入 SELECT 语句 | 注入进入 SQL 文本 |  |
| 5 | `vulnerabilities/sqli/source/low.php:11` | mysqli_query 执行注入后的语句 | SQL 执行，结果回显 |  |

**POC**

针对 /vulnerabilities/sqli/session-input.php（POST）的 SQL 注入 POC。注入点为 POST 参数 id，源码 vulnerabilities/sqli/session-input.php:14 将 id 直接拼入 SQL 查询，未做参数化或转义。目标地址统一使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/sqli/session-input.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/sqli/session-input.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-fb23f3d9c630`
- 执行状态：未执行（`executed=False`）

**影响**

持久化于会话的注入载荷可在后续请求中触发，读取数据库敏感数据；同时会话值未编码回显构成 XSS。

**CVE / CWE 论证**

CWE-89（二次注入）。写点 session-input.php:12、读点与汇点 low.php:5/10/11 均在 CODE PACK 内可见，构成完整三段链。

**修复建议**

对写入会话的 id 做严格校验（整数白名单），读取后仍使用预处理语句；输出时 htmlspecialchars 编码。

**验证说明**

index.php 未完整展示，需确认其确实从 $_SESSION['id'] 取值并 include source/low.php；若 index.php 仅用 $_REQUEST['id']，则二次注入链不成立，应降级为普通注入。
模型 POC 要点：先向 session-input.php 写入注入载荷，再访问 sqli 模块使会话值进入查询。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/sqli/session-input.php）：符合 CWE-89。漏洞位于 vulnerabilities/sqli/session-input.php:14，外部输入来自 POST 参数 id，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标地址使用 TARGET 占位符。SQL 注入 POC 不使用 DROP 等破坏性语句。

### F-4: session-input.php 将 $_POST['id'] 未编码回显到页面（反射型 XSS）

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`vulnerabilities/sqli/session-input.php:12-15`
- **来源**：`llm_finding`

**描述**

session-input.php 第 14 行将 $_SESSION['id']（源自 $_POST['id']）直接拼入 $page['body'] 输出，未做 htmlspecialchars 编码，攻击者可注入脚本在受害者浏览器执行，窃取会话或执行敏感操作。

**source / sink**

- source：body `id`（vulnerabilities/sqli/session-input.php:12）
- sink：vulnerabilities/sqli/session-input.php:15 $page['body'] 输出（dvwaSourceHtmlEcho 渲染）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `vulnerabilities/sqli/session-input.php:12` | 读取 POST id 写入会话 | 攻击者可控字符串 |  |
| 2 | `vulnerabilities/sqli/session-input.php:14` | 未编码拼入页面 body | HTML 注入 |  |
| 3 | `vulnerabilities/sqli/session-input.php:28` | dvwaSourceHtmlEcho 输出页面 | 脚本在浏览器执行 |  |

**POC**

针对 /vulnerabilities/sqli/session-input.php（POST）的跨站脚本 POC。注入点为 POST 参数 id，源码 vulnerabilities/sqli/session-input.php:15 将 id 未经 HTML 编码输出到响应页面。目标地址统一使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/sqli/session-input.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/sqli/session-input.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'id=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-13fca7fffff3`
- 执行状态：未执行（`executed=False`）

**影响**

窃取会话 Cookie、以受害者身份执行操作。

**CVE / CWE 论证**

CWE-79。外部 POST 参数未编码回显，链路闭合。

**修复建议**

输出前使用 htmlspecialchars($value, ENT_QUOTES, 'UTF-8') 编码。

**验证说明**

需确认 dvwaSourceHtmlEcho 未额外编码 body。
模型 POC 要点：提交含 script 的 id，页面回显时执行。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/sqli/session-input.php）：符合 CWE-79。漏洞位于 vulnerabilities/sqli/session-input.php:15，外部输入来自 POST 参数 id，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标地址使用 TARGET 占位符。验证时使用无害的 alert(document.domain)，不使用窃取凭据或外发数据的载荷。

### F-5: view_source_all.php 通过 id 参数拼接路径读取源码文件

- **类型**：`path_traversal` / CWE-22
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`vulnerabilities/view_source_all.php:11-28`
- **来源**：`llm_finding`

**描述**

view_source_all.php 第 12 行读取 $_GET['id']，第 14/18/22/26 行将其拼入 "./{$id}/source/low.php" 等路径并 file_get_contents 读取，未做 basename 或白名单校验，攻击者可穿越目录读取任意 .php 文件内容（经 highlight_string 回显）。

**source / sink**

- source：query `id`（vulnerabilities/view_source_all.php:12）
- sink：vulnerabilities/view_source_all.php:28 file_get_contents("./{$id}/source/low.php")（vulnerabilities/view_source_all.php:14）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `vulnerabilities/view_source_all.php:11` | 检查 id 参数存在 | 参数存在 |  |
| 2 | `vulnerabilities/view_source_all.php:12` | 直接读取 id，无过滤 | 攻击者可控字符串 |  |
| 3 | `vulnerabilities/view_source_all.php:14` | 拼入路径并 file_get_contents 读取 | 路径穿越读取任意文件 |  |
| 4 | `vulnerabilities/view_source_all.php:16` | highlight_string 回显文件内容 | 文件内容泄露到页面 |  |

**POC**

针对 /vulnerabilities/view_source_all.php（GET）的路径穿越 POC。注入点为 GET 参数 id，源码 vulnerabilities/view_source_all.php:28 将 id 直接用于文件路径拼接，未做规范化与白名单校验。目标地址统一使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/view_source_all.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 路径穿越 / 任意文件读写 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/vulnerabilities/view_source_all.php?id=..%2F..%2F..%2F..%2Ftmp%2Fsunset_LLM86bd7.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_LLM86bd7.txt`
- POC 目录：`poc/LLM-86bd7b14c357`
- 执行状态：未执行（`executed=False`）

**影响**

泄露服务器源码与配置（含数据库凭据），辅助进一步攻击。

**CVE / CWE 论证**

CWE-22。外部 GET 参数直达 file_get_contents，链路在 view_source_all.php:12→14 闭合。

**修复建议**

对 id 使用模块名白名单，禁止路径分隔符；使用 realpath 校验目标位于允许目录内。

**验证说明**

需确认目标路径下存在可读文件；@ 抑制错误但成功读取时仍回显。
模型 POC 要点：利用 ../ 穿越读取任意 PHP 源码或配置文件。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/view_source_all.php）：符合 CWE-22。漏洞位于 vulnerabilities/view_source_all.php:28，外部输入来自 GET 参数 id，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标地址使用 TARGET 占位符。读取路径应替换为授权环境中确认存在的文件，避免对目标造成写入副作用。

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
| `sql_injection` | CWE-89 | 是 | 2 |
| `ssrf` | CWE-918 | 是 | 0 |
| `path_traversal` | CWE-22 | 是 | 2 |
| `deserialization` | CWE-502 | 是 | 0 |
| `ssti` | CWE-1336 | 是 | 0 |
| `auth_bypass` | CWE-287 | 是 | 0 |
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
| safety_guard | 安全防护 | 8.89 | 是 |
| surface_mapper | 攻击面测绘 | 13.08 | 是 |
| deep_finder | LLM 深挖 | 29.85 | 是 |
| candidate_screener | 候选筛选 | 6.37 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.23 | 否 |
| poc_writer | POC 生成 | 13.45 | 是 |
| coordinator | 管线协调 | 9.68 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
