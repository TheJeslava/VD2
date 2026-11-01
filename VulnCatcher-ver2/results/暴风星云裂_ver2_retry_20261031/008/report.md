# 落日二号乙漏洞挖掘报告 — 20261031-001750-341e2f

- 生成时间：2026-10-30T16:18:47.028388+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\008.zip`
- 输入模式：`zip`
- SHA256：`dfae4e0605b1c5ffe8c4a8291c00c73ea277b830eed60f0489dfec01c43f36a6`
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

本次汇总基于单文件 PHP 应用 008.php（96 行）的已去重 findings：共 4 条，全部带 POC 文本工件（未执行、未动态验证）。最高危为 3 条 critical 级 SQL 注入（CWE-89）：008.php 第 23 行用户存在性检查、第 36 行用户信息查询、第 81 行日志 INSERT 写入，均为请求参数直接拼接 SQL 的一次注入；另有 1 条 high 级 IDOR/BAC（LLM-be8d58eeb7fa，第 47 行），通过可篡改的 user_id Cookie 越权读取任意用户资料。POC 齐全度为 4/4，但均为静态/文本 POC，SQL 注入类可构造 HTTP 请求复现（目标用 TARGET 占位），IDOR 需结合会话语义复核。二次注入三段链（存储写点—存储读点—读取后危险汇点）在本次 findings 中未被单独标注，第 81 行写入与第 36 行读取是否构成二次注入链需人工确认，不得与一次注入混为一谈。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3377 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 008.php 可见的 1-65 行（共 96 行，66-96 行未送入）。确认一条闭合的越权链：访问控制仅比较客户端 Cookie user_id 与请求参数 user_id，未绑定会话真实用户，导致任意用户资料读取（IDOR/BAC，高）。另记录输出未编码的 XSS 面，但存储写点不在 CODE PACK 内，链未闭合，置信度 0.6。SQL 拼接处（第 7、22、35 行）参数均经 intval 或来自 dvwaCurrentUser()，未发现可闭合的 SQL 注入。第 60-65 行 bac_log 建表逻辑及 66-96 行未覆盖，可能存在日志写入相关二次注入或其它逻辑，需后续补充。

未覆盖 / 证据缺口：
- 008.php 第 66-96 行未送入，bac_log 日志写入与后续读取逻辑未审计
- 无端点/路由清单，实际访问路径与参数名基于代码推断
- 无认证/会话实现，无法确认 Cookie user_id 是否被其它层覆盖
- 资料字段写入点不在 CODE PACK，XSS 存储链未闭合

## 3. Findings

### F-1: 008.php 用户存在性检查处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:21-23`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 user_id 提供输入（008.php:19 读取），该值被直接拼接进 $check_query 字符串："SELECT user_id FROM users WHERE user_id = $id"（008.php:22），随后在 008.php:23 交给 mysqli_query 执行。代码未使用 mysqli_prepare/bind_param，也未对 $id 做类型强制转换（如 intval）或转义，因此单引号、UNION、布尔/时间盲注等载荷可改变 SQL 语义。该查询位于用户存在性检查分支，属于登录/访问流程的前置逻辑，外部无需认证即可触达。

**source / sink**

- source：query `user_id`（008.php:19）
- sink：008.php:23 $check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:19` | 从 query `user_id` 读取外部输入 | 污点进入 check_query |  |
| 2 | `008.php:23` | 危险汇点：$check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /008（任意方法）的 SQL 注入 POC，注入点为查询参数 user_id，漏洞代码位于 008.php:23。payload 使用 TARGET 占位符，仅作文本工件。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/008?user_id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-f0aa8e8c7f6b`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库数据泄露（users 表及其他表可被 UNION 读取，包括口令哈希）、通过布尔/时间盲注逐字节提取数据；若数据库账号权限过高，还可导致数据篡改。属于未认证远程 SQL 注入。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达：user_id 来自 HTTP 查询参数；无需认证：检查逻辑在鉴权判定之前执行；利用链闭合：008.php:19 取值 → 008.php:22 字符串拼接 → 008.php:23 mysqli_query 执行，中间无有效净化。

**修复建议**

改用预处理语句：$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "SELECT user_id FROM users WHERE user_id = ?"); mysqli_stmt_bind_param($stmt, "i", $id); 并对 $id 做 intval 白名单校验；同时以最小权限数据库账号运行，关闭详细错误回显。

**验证说明**

静态证据：入口 ANY /008；source=query/user_id；sink=008.php:23；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 008.php?user_id=1 UNION SELECT ... → 008.php:19 读取 user_id 到 $id → 008.php:22 拼入 $check_query → 008.php:23 mysqli_query 执行被篡改的 SQL → 结果影响后续分支判断并回显/影响响应。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。漏洞位于 008.php:23，外部输入来自查询参数 user_id，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构；脚本仅为文本，不执行、不联网。目标统一使用 TARGET 占位符，仅限授权测试。

### F-2: 008.php 用户信息查询处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:34-36`
- **来源**：`rule`

**描述**

同一外部输入 user_id（008.php:31 读取）在通过存在性检查后，被再次拼接进 $query："SELECT first_name, last_name, user_id, avatar FROM users WHERE user_id = $id;"（008.php:35），并在 008.php:36 由 mysqli_query 执行。此处同样无参数化、无类型转换、无转义，且查询结果（姓名、头像等）通常会回显到页面，构成可直接回显的注入点。

**source / sink**

- source：query `user_id`（008.php:31）
- sink：008.php:36 $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:31` | 从 query `user_id` 读取外部输入 | 污点进入 query |  |
| 2 | `008.php:36` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"], $query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /008（任意方法）的 SQL 注入 POC，注入点为查询参数 user_id，漏洞代码位于 008.php:36。payload 使用 TARGET 占位符，仅作文本工件。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/008?user_id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-efda4d219748`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可读取任意 users 记录字段（first_name/last_name/avatar 等），结合 UNION 可跨表读取敏感数据；回显型注入使数据外带更直接。未认证远程可利用。

**CVE / CWE 论证**

CWE-89。外部可达：user_id 为 HTTP 查询参数；无需认证：该分支在访问授权判定通过后即执行，而授权判定本身可被前一处注入绕过；利用链闭合：008.php:31 → 008.php:35 拼接 → 008.php:36 执行，无净化。

**修复建议**

使用 mysqli_prepare + bind_param("i", $id) 参数化；对 $id 做 intval 校验；输出到 HTML 时使用 htmlspecialchars 防止二次问题；数据库账号最小权限。

**验证说明**

静态证据：入口 ANY /008；source=query/user_id；sink=008.php:36；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 user_id=1 UNION SELECT ... → 008.php:31 取值 → 008.php:35 拼接进 $query → 008.php:36 执行 → 结果集被渲染，泄露任意表数据。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。漏洞位于 008.php:36，外部输入来自查询参数 user_id，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构；脚本仅为文本，不执行、不联网。目标统一使用 TARGET 占位符，仅限授权测试。

### F-3: 008.php 日志写入 INSERT 处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.63`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:79-81`
- **来源**：`rule`

**描述**

在日志记录逻辑中，$log_query 由 {$current_user_id}、{$target_id} 与 '{$ip}' 直接插值拼接而成（008.php:79-80），并在 008.php:81 由 mysqli_query 执行。其中 $target_id 与 $current_user_id 的取值链上游包含外部 user_id 输入（008.php:31），$ip 来自请求环境（如 REMOTE_ADDR 或转发头），均未参数化或转义。攻击者可通过控制 target_id 或伪造 IP 头注入任意 SQL 片段。

**source / sink**

- source：query `user_id`（008.php:31）
- sink：008.php:81 mysqli_query($GLOBALS["___mysqli_ston"], $log_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:31` | 从 query `user_id` 读取外部输入 | 污点进入 log_query |  |
| 2 | `008.php:81` | 危险汇点：mysqli_query($GLOBALS["___mysqli_ston"], $log_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /008（任意方法）的 SQL 注入 POC，注入点为查询参数 user_id，漏洞代码位于 008.php:81。payload 使用 TARGET 占位符，仅作文本工件。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/008?user_id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-31888d7d7e9c`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可向 bac_log 表写入伪造记录、通过子查询/报错注入读取其他表数据，或利用 INSERT ... SELECT 造成数据污染；若堆叠查询被驱动允许，影响进一步扩大。未认证远程可利用。

**CVE / CWE 论证**

CWE-89。外部可达：target_id 源自 user_id 参数链，$ip 源自请求头；无需认证：日志写入在业务分支内自动触发；利用链闭合：008.php:31 → 008.php:79-80 字符串插值 → 008.php:81 执行，无净化。

**修复建议**

对 INSERT 使用预处理语句并绑定 (user_id, target_id, ip_address) 三个参数；$ip 使用 filter_var(FILTER_VALIDATE_IP) 校验并只信任受控代理头；对 id 类字段强制 intval；数据库账号仅授予 INSERT 所需列权限。

**验证说明**

静态证据：入口 ANY /008；source=query/user_id；sink=008.php:81；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 user_id=1 并控制 target_id/伪造 X-Forwarded-For → 008.php:31 取值 → 008.php:79-80 插值进 $log_query → 008.php:81 执行 → 注入的 SQL 片段生效，污染日志表或借报错/子查询外带数据。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。漏洞位于 008.php:81，外部输入来自查询参数 user_id，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构；脚本仅为文本，不执行、不联网。目标统一使用 TARGET 占位符，仅限授权测试。

### F-4: DVWA 008.php 通过可篡改的 user_id Cookie 实现越权访问任意用户资料（BAC/IDOR）

- **类型**：`idor` / CWE-639
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`008.php:30-47`
- **来源**：`llm_finding`

**描述**

008.php 的访问控制完全依赖客户端 Cookie `user_id`：脚本读取 `$_COOKIE['user_id']` 并仅用 `intval()` 转换后与请求参数 `user_id` 比较（第 30-33 行），相等即放行并查询该用户资料（第 35-47 行）。服务端从未将 Cookie 与当前登录会话（`dvwaCurrentUser()` 查得的 `$current_user_id`）绑定，攻击者只需把 Cookie 改成目标用户 ID 即可读取任意用户 first_name/last_name/avatar。这是典型的失效访问控制/IDOR（CWE-639/CWE-284）。

**source / sink**

- source：cookie `user_id`（008.php:15）
- sink：008.php:47 mysqli_query 查询 users 表并回显 first_name/last_name/avatar（008.php:35-47）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:15` | 入口读取 $_GET['action'] 与 $_GET['user_id'] | 外部可控字符串 |  |
| 2 | `008.php:16-19` | preg_match 仅校验纯数字，随后 intval 转为整数 $id | 整数 $id（攻击者指定目标用户） |  |
| 3 | `008.php:30-33` | 读取 $_COOKIE['user_id'] 转 intval 后与 $id 比较，相等即授权 | 攻击者同时控制 Cookie 与参数，可令二者相等 | 授权判断只比较两个均由客户端提供的值，未与会话中的真实用户 ID 绑定 |
| 4 | `008.php:35-47` | 以 $id 查询并回显目标用户资料 | 目标用户敏感字段被输出 |  |

**POC**

针对 /008.php（GET）的越权/IDOR POC，注入点为 Cookie user_id，漏洞代码位于 008.php:47。payload 使用 TARGET 占位符，仅作文本工件。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 越权 / IDOR 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/008.php' \
  -H 'Cookie: user_id=2'
```
预期：使用其他对象 ID 返回他人数据或执行他人操作。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`2`
- POC 目录：`poc/LLM-be8d58eeb7fa`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

任意已登录用户可枚举并读取所有用户（含管理员）的姓名、头像等资料，构成水平/垂直越权信息泄露。

**CVE / CWE 论证**

CWE-639 授权绕过；外部单请求可达，无需高权限，链路在 008.php 内闭合。

**修复建议**

服务端应使用会话中的 $current_user_id 做归属校验，忽略客户端 Cookie 中的 user_id；对敏感资料查询强制 WHERE user_id = $current_user_id。

**验证说明**

需确认部署中 Cookie user_id 未被服务端其它层覆盖；DVWA 环境默认存在 admin 用户 ID=1。
模型 POC 要点：将 Cookie user_id 设为受害者 ID，同时请求相同 user_id 参数，绕过归属校验读取他人资料。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /008.php）：符合 CWE-639。漏洞位于 008.php:47，外部输入来自 Cookie user_id，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构；脚本仅为文本，不执行、不联网。目标统一使用 TARGET 占位符，仅限授权测试。

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
| `sql_injection` | CWE-89 | 是 | 3 |
| `ssrf` | CWE-918 | 是 | 0 |
| `path_traversal` | CWE-22 | 是 | 0 |
| `deserialization` | CWE-502 | 是 | 0 |
| `ssti` | CWE-1336 | 是 | 0 |
| `auth_bypass` | CWE-287 | 是 | 0 |
| `idor` | CWE-639 | 是 | 1 |
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
| safety_guard | 安全防护 | 3.54 | 是 |
| surface_mapper | 攻击面测绘 | 12.03 | 是 |
| deep_finder | LLM 深挖 | 10.44 | 是 |
| candidate_screener | 候选筛选 | 5.5 | 是 |
| vulnerability_analyzer | 漏洞分析 | 8.7 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 8.65 | 是 |
| coordinator | 管线协调 | 7.09 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
