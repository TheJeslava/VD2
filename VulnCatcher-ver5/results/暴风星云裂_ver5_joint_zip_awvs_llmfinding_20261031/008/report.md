# 落日二号乙漏洞挖掘报告 — 20261031-214043-fb14b4

- 生成时间：2026-10-31T13:41:55.994446+00:00
- 输入：`$WORKSPACE\暴风星云裂\008.zip`
- 输入模式：`zip`
- SHA256：`dfae4e0605b1c5ffe8c4a8291c00c73ea277b830eed60f0489dfec01c43f36a6`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.5.0-ver5
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次审计对象为单文件 PHP 脚本 008.php（96 行），共交付 6 条去重后发现，全部带 POC 文本（静态构造，未执行、未动态验证）。最高危为 3 条 critical 级 SQL 注入（CWE-89）：GEN-31888d7d7e9c（日志写入处，line_end=81）、GEN-f0aa8e8c7f6b（用户存在性检查，line_end=23）、GEN-efda4d219748（用户信息查询，line_end=36），均为规则命中、污点路径短。其次为 high 级 GEN-efda4d219748 之外的 LLM-be8d58eeb7fa（通过可篡改 user_id Cookie 越权读取任意用户资料，IDOR，line_end=47）与 SEM-e3f1dc6ea55d（基于 Cookie 的角色标识可预测/可伪造，weak_id，CWE-330/CWE-565，line_end=94）；medium 级 LLM-3ee4fdec5d75 为用户资料字段未转义导致的存储型 XSS（line_end=47）。POC 齐全度为 6/6，但均为文本工件，SQL 注入与 XSS 类可作 HTTP 复现参考，weak_id 属静态/会话语义证据，不能宣称已动态复现。

共 **6** 条 finding；**6** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3377 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 008.php 第 1-65 行（code_pack 仅提供 1-65，66-96 行未送入）。确认存在 IDOR：归属校验依赖客户端 Cookie user_id（30-33 行），可篡改读取任意用户资料（35-47 行），链闭合，置信度高。另发现资料字段未转义输出（40-47 行）的潜在存储型 XSS，但写入点不在 code_pack 内，链未闭合，置信度低。第 7 行 dvwaCurrentUser() 拼接 SQL 但来源为服务端会话用户名，非直接外部可控，未单列。第 60-65 行 bac_log 建表逻辑为固定 SQL，无注入。66-96 行（日志写入等）未提供，未覆盖。

未覆盖 / 证据缺口：
- 008.php 第 66-96 行未送入 code_pack
- 缺少资料写入点代码，XSS 链未闭合
- 缺少 Web 服务器/php.ini 配置，无法确认可达性与 allow_url_include
- dvwaCurrentUser() 实现未提供，无法完全排除其返回值外部可控

## 3. Findings

### F-1: 008.php 日志写入 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:79-81`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 user_id（008.php:19 读取）提交恶意字符串，该值被赋给 $id 后未做类型转换或参数化，直接以字符串插值方式拼入 $log_query（008.php:79-80：INSERT INTO bac_log (user_id, target_id, ip_address) VALUES ({$current_user_id}, {$target_id}, '{$ip}')），随后在 008.php:81 交给 mysqli_query 执行。由于 $current_user_id 位置没有引号包裹，攻击者只需在 user_id 中构造如 1) 或 1,2,'x')-- - 之类的片段即可闭合 VALUES 列表并注入任意 SQL 表达式或子查询，校验完全缺失（无 intval、无 mysqli_real_escape_string、无预处理语句）。

**source / sink**

- source：query `user_id`（008.php:19）
- sink：008.php:81 mysqli_query($GLOBALS["___mysqli_ston"], $log_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:19` | 从 query `user_id` 读取外部输入 | 污点进入 log_query |  |
| 2 | `008.php:81` | 危险汇点：mysqli_query($GLOBALS["___mysqli_ston"], $log_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /008（GET）的 SQL 注入 POC。注入点：GET 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/008?user_id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-31888d7d7e9c`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可对后端数据库执行任意 INSERT/SELECT 子查询，导致日志表数据被伪造或污染、通过报错/布尔/时间盲注逐位读取 users 等表的敏感数据（口令哈希、用户名），在数据库账号权限较高时可进一步写入文件或篡改业务数据。

**CVE / CWE 论证**

CWE-89：外部可控的 query 参数 user_id 未经任何净化进入 SQL 语句构造，最终由 mysqli_query 执行，攻击路径为 008.php:19 → $id → 008.php:79-80 $log_query → 008.php:81 mysqli_query，链路闭合；该脚本为可直接 HTTP 访问的 PHP 页面，无需认证即可触发，符合远程可利用的 SQL 注入判定。

**修复建议**

改用预处理语句与参数绑定（mysqli_prepare + bind_param，user_id/target_id 用 i 类型，ip 用 s 类型）；若必须拼接，先对 user_id 做 (int) 强制转换、对 ip 使用 mysqli_real_escape_string 并加引号；同时为数据库账号授予最小权限（仅 INSERT 到 bac_log），关闭详细错误回显。

**验证说明**

静态证据：入口 GET /008；source=query/user_id；sink=008.php:81；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求 GET/POST 参数 user_id → 008.php:19 读取并赋给 $id → 未净化直接进入 008.php:79-80 的 $log_query 字符串插值（{$current_user_id} 无引号包裹，最易闭合）→ 008.php:81 mysqli_query 执行，注入生效。
PocWriter 建议（未采纳，缺少端点 /008）：针对 008.php:81 的 SQL 注入 POC。注入点为 GET 参数 user_id，源码在该行将外部输入拼接进 SQL 查询，未使用参数化。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。漏洞位于 008.php:81，外部输入来自 GET 参数 user_id，source→sink 链在给定代码范围内静态闭合，未发现有效净化或参数化查询。
POC 备注：仅文本工件，不执行。保留原请求结构，补充了布尔假条件对照步骤以增强可复现性。执行前将 TARGET 替换为授权测试实例。

### F-2: 008.php 用户存在性检查 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.63`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:21-23`
- **来源**：`rule`

**描述**

同一外部输入 user_id（008.php:19）在进入存在性校验时被直接拼入 $check_query（008.php:22：SELECT user_id FROM users WHERE user_id = $id），并在 008.php:23 由 mysqli_query 执行。$id 位于数值上下文且无引号，攻击者可提交 1 OR 1=1、1 UNION SELECT ... 或 1 AND SLEEP(5) 等载荷，绕过存在性判断或注入联合查询。代码中没有任何类型校验、转义或参数化。

**source / sink**

- source：query `user_id`（008.php:19）
- sink：008.php:23 $check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:19` | 从 query `user_id` 读取外部输入 | 污点进入 check_query |  |
| 2 | `008.php:23` | 危险汇点：$check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /008（GET）的 SQL 注入 POC。注入点：GET 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/008?user_id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-f0aa8e8c7f6b`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可绕过用户存在性校验逻辑（使任意/不存在的 ID 被判为存在），并通过 UNION/布尔/时间盲注读取 users 表任意列（如口令哈希、邮箱），造成敏感数据泄露；也可作为后续越权访问分支的入口。

**CVE / CWE 论证**

CWE-89：query 参数 user_id 经 $id 直接拼接进 SELECT 语句，在 008.php:23 执行，source→sink 链路完整（008.php:19 → 008.php:22 → 008.php:23），页面可匿名 HTTP 访问，无需认证。

**修复建议**

使用 mysqli_prepare 绑定整型参数（bind_param('i', $id)）；或在拼接前强制 (int)$id 并校验范围；统一封装数据库访问层，禁止字符串拼接 SQL；限制数据库账号对 users 表的读取权限。

**验证说明**

静态证据：入口 GET /008；source=query/user_id；sink=008.php:23；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：user_id 参数 → 008.php:19 $id → 008.php:22 $check_query 数值位置拼接 → 008.php:23 mysqli_query 执行，注入生效。
PocWriter 建议（未采纳，缺少端点 /008）：针对 008.php:23 的 SQL 注入 POC。注入点为 GET 参数 user_id，源码在该行将外部输入拼接进 SQL 查询。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。漏洞位于 008.php:23，外部输入来自 GET 参数 user_id，source→sink 链在给定代码范围内静态闭合，未发现有效净化。
POC 备注：仅文本工件，不执行。保留原请求结构，补充布尔假条件对照步骤。执行前将 TARGET 替换为授权测试实例。

### F-3: 008.php 用户信息查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.63`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:34-36`
- **来源**：`rule`

**描述**

在通过前述校验后，$id 再次被拼入 $query（008.php:35：SELECT first_name, last_name, user_id, avatar FROM users WHERE user_id = $id;），并在 008.php:36 由 mysqli_query 执行。该处同样无参数化、无转义，攻击者可用 UNION SELECT 追加任意列或子查询，把结果集替换为攻击者控制的数据。

**source / sink**

- source：query `user_id`（008.php:19）
- sink：008.php:36 $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:19` | 从 query `user_id` 读取外部输入 | 污点进入 query |  |
| 2 | `008.php:36` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"], $query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /008（GET）的 SQL 注入 POC。注入点：GET 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/008?user_id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-efda4d219748`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可通过 UNION 注入读取任意表数据（如 users 口令哈希、其他业务表），或篡改返回的用户资料展示内容；结合页面回显可形成稳定的数据泄露通道。

**CVE / CWE 论证**

CWE-89：外部 query 参数 user_id 经 $id 进入 008.php:35 的 SELECT 拼接，在 008.php:36 执行，链路 008.php:19 → 008.php:35 → 008.php:36 闭合，HTTP 直接可达且无需认证。

**修复建议**

改为预处理语句并绑定整型参数；对输出到页面的字段做 HTML 转义以防二次问题；对 users 表查询使用只读最小权限账号；增加统一输入校验（user_id 必须为纯数字）。

**验证说明**

静态证据：入口 GET /008；source=query/user_id；sink=008.php:36；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：user_id 参数 → 008.php:19 $id → 008.php:35 $query 拼接 → 008.php:36 mysqli_query 执行并回显结果，注入生效。
PocWriter 建议（未采纳，缺少端点 /008）：针对 008.php:36 的 SQL 注入 POC。注入点为 GET 参数 user_id，源码在该行将外部输入拼接进 SQL 查询。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。漏洞位于 008.php:36，外部输入来自 GET 参数 user_id，source→sink 链在给定代码范围内静态闭合，未发现有效净化。
POC 备注：仅文本工件，不执行。保留原请求结构，补充布尔假条件对照步骤。执行前将 TARGET 替换为授权测试实例。

### F-4: DVWA BAC 页面通过可篡改 user_id Cookie 越权读取任意用户资料

- **类型**：`idor` / CWE-639
- **严重度**：`high`
- **置信度**：`0.96`
- **结论**：`candidate` / 证据等级 `externally_corroborated`
- **位置**：`008.php:30-47`
- **来源**：`llm_finding`

**描述**

008.php 的访问控制完全依赖客户端 Cookie `user_id`：第 30-33 行读取 `$_COOKIE['user_id']` 并与请求参数 `$_GET['user_id']` 比较，相等即视为“本人”并放行第 35-47 行的资料查询与回显。Cookie 由攻击者完全控制，只要把 Cookie 的 user_id 改成目标 ID，即可通过 `id == cookie_id` 校验，读取任意用户的 first_name/last_name/avatar。服务端从未用会话中的真实身份（第 7-11 行查出的 $current_user_id）做归属校验，属于典型的水平越权（IDOR）。

**source / sink**

- source：cookie `user_id`（008.php:15）
- sink：008.php:47 008.php:35-36 使用 $id 查询 users 表并 008.php:43-45 回显他人资料

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:15` | 入口读取 action 与 user_id 参数 | $_GET['user_id'] 为攻击者可控字符串 |  |
| 2 | `008.php:16-19` | 仅用正则 ^\d+$ 校验格式后 intval 转换 | $id 为纯数字，但取值任意 | 格式校验不限制取值范围，任意数字均通过 |
| 3 | `008.php:30-33` | 读取客户端 Cookie user_id 并与 $id 比较 | $cookie_id 完全由攻击者设置，可令其等于 $id | 归属校验依据客户端 Cookie 而非服务端会话身份 |
| 4 | `008.php:35-47` | 校验通过后查询并回显目标用户资料 | $id 拼入 SELECT 并输出 first_name/last_name/avatar |  |

**POC**

针对 /008.php（GET）的 越权 / IDOR POC。注入点：查询 user_id=2 与 Cookie user_id=1 的对象归属对照；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 越权 / IDOR 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/008.php?action=View%20Profile&user_id=2' -H 'Cookie: user_id=1'
```
预期：返回用户 ID=2 的资料，即使 Cookie 表示当前用户 ID=1

3. **将 user_id 改为当前用户 ID 做对照**

```http
curl -sS -i -X GET 'http://TARGET:8080/008.php?action=View%20Profile&user_id=1' -H 'Cookie: user_id=1'
```
预期：对照响应只返回当前用户资料，攻击响应返回另一用户资料

- payload：`2`
- POC 目录：`poc/LLM-be8d58eeb7fa`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

任意已认证用户可枚举并读取全部用户（含管理员）的姓名、头像等资料，构成水平/垂直越权信息泄露。

**CVE / CWE 论证**

CWE-639 授权绕过（IDOR）。外部 HTTP 可达，仅需低权限账户，链闭合：Cookie 可控 -> 比较通过 -> 查询回显。

**修复建议**

使用服务端会话中的真实用户 ID（$current_user_id）与请求的 $id 比较，禁止信任客户端 Cookie 做归属判断；对敏感字段做角色校验。

**验证说明**

需确认 DVWA 会话中是否存在独立可信身份来源；确认 users 表存在且 user_id=1 为有效用户。
模型 POC 要点：将 Cookie user_id 设为与请求参数 user_id 相同的目标 ID，绕过归属校验读取他人资料
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
AWVS 外部佐证：Insecure Direct Object Reference @ http://127.0.0.1:18081/008.php（未在本管线执行扫描）。
PocWriter 建议（未采纳，缺少端点 /008.php）：针对 008.php:47 的 IDOR（越权访问）POC。源码以 Cookie user_id 作为当前用户身份，同时接受查询参数 user_id 指定要查看的对象，未校验两者归属关系。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /008.php）：符合 CWE-639。漏洞位于 008.php:47，身份来源为 Cookie user_id，对象选择来自查询参数 user_id，二者未做归属校验，source→sink 链在给定代码范围内静态闭合。
POC 备注：仅文本工件，不执行。三步均保持同一 Cookie（user_id=1），仅改变查询参数 user_id，以证明越权。执行前将 TARGET 替换为授权测试实例。

**外部佐证**

- awvs: Insecure Direct Object Reference @ http://127.0.0.1:18081/008.php

### F-5: 008.php 基于 Cookie 的角色标识可预测/可伪造（CWE-330/CWE-565）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:93-94`
- **来源**：`rule`

**描述**

008.php:93-94 在 $_COOKIE['user_role'] 不存在时，用 setcookie('user_role','regular_user', time()+3600, '/') 下发角色标识。该标识是固定字面量而非随机令牌，且完全由客户端 Cookie 承载，服务端未做签名或与服务器端会话绑定；攻击者可直接把 Cookie user_role 改为其他角色值（如 admin）尝试提权。候选将其归类为弱 ID/可预测标识，但代码片段中并未出现随机数或时间派生 ID 的生成逻辑，仅见固定值下发，因此“时间/递增派生”的语义判断证据不足，实际风险更偏向客户端可控的信任边界问题。

**source / sink**

- source：session `dvwaSession`（008.php）
- sink：008.php:94     setcookie('user_role', 'regular_user', time() + 3600, '/');

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:94` | 会话标识由时间/递增值派生；需跨请求预测并确认服务端接受 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /008（POST）的 弱 ID / 可预测会话标识 POC。注入点：POST 会话建立请求；连续请求比较 dvwaSession Cookie；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **在保持同一会话的情况下第一次 POST，记录 Set-Cookie**

```http
curl -sS -i -b "${cookie_jar}" -c "${cookie_jar}" -X POST 'http://TARGET:8080/008' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：返回 dvwaSession 等会话 Cookie，记录其值

3. **保持同一会话再次 POST，并比较两次会话 Cookie**

```http
curl -sS -i -b "${cookie_jar}" -c "${cookie_jar}" -X POST 'http://TARGET:8080/008' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：Cookie 值出现连续递增/可预测序列

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-e3f1dc6ea55d`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若服务端后续逻辑依据 user_role Cookie 做授权判断，攻击者可伪造角色实现越权访问；由于值为固定字符串，无需预测即可直接设置。

**CVE / CWE 论证**

CWE-330（使用不充分的随机值）/CWE-565（依赖未经验证的 Cookie）：角色标识以固定字面量写入客户端 Cookie，未签名、未与服务器端会话绑定，客户端可任意修改。外部可达性成立（任意 HTTP 请求即可设置 Cookie），但“时间/递增派生”的具体生成逻辑在给定片段中未见，需运行时或跨文件复核才能确认弱随机部分。

**修复建议**

不要在客户端 Cookie 中存放授权角色；改用服务器端会话（$_SESSION）保存角色，并对会话 Cookie 设置 HttpOnly、Secure、SameSite；如需客户端令牌，使用 HMAC 签名并校验完整性；授权判断一律以服务端数据为准。

**验证说明**

静态证据：入口 POST /008；source=session/dvwaSession；sink=008.php:94；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：客户端请求携带/缺失 user_role Cookie → 008.php:93 判断 → 008.php:94 下发固定值 regular_user → 客户端可任意改写该 Cookie → 若下游授权逻辑信任该值则形成越权。弱随机派生环节证据不足。
PocWriter 建议（未采纳，缺少端点 /008）：针对 008.php:94 的弱会话 ID（可预测）POC。源码在该行附近生成 dvwaSession Cookie，值呈可预测序列。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-330。漏洞位于 008.php:94，会话标识 dvwaSession 生成方式可预测，source→sink 链在给定代码范围内静态闭合。
POC 备注：仅文本工件，不执行。三步均保持同一会话（Cookie 传递），通过连续请求比较 dvwaSession 值。执行前将 TARGET 替换为授权测试实例。

### F-6: 008.php 用户资料字段未转义直接输出导致存储型 XSS

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.52`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`008.php:40-47`
- **来源**：`llm_finding`

**描述**

第 40-47 行将数据库取出的 first_name/last_name/avatar 直接拼接进 HTML 输出，未做 htmlspecialchars 转义。若这些字段可由用户（如注册/资料编辑处）写入，则构成存储型 XSS；即便仅管理员可写，也可在管理员查看时触发。

**source / sink**

- source：repository `first_name,last_name,avatar`（008.php）
- sink：008.php:47 008.php:44-45 字符串拼接进 $html 输出

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:35-39` | 从 users 表取出资料字段 | 数据库中的 first_name/last_name/avatar |  |
| 2 | `008.php:44-45` | 未转义直接拼入 HTML | 原样输出到响应 HTML |  |

**POC**

针对 008.php:47 的存储型/反射型 XSS 候选 POC。源码在该行将数据库字段 first_name、last_name、avatar 直接拼接进 HTML 输出，未做 HTML 编码。目标地址使用 TARGET 占位符，仅限授权测试。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 008.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-3ee4fdec5d75`
- 风险提示：HTTP POC 未使用 TARGET 占位符, 请求未包含 finding 端点 /008.php, 请求未体现 HTTP 方法 GET, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码, POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

可窃取会话或执行敏感操作（取决于写入点可达性）。

**CVE / CWE 论证**

CWE-79。输出未转义，但写入点不在 code_pack 内，链未完全闭合。

**修复建议**

输出前对 first_name/last_name/avatar 使用 htmlspecialchars 转义。

**验证说明**

缺少资料写入点代码，无法确认字段是否用户可控；若仅管理员可写则价值下降。
模型 POC 要点：若资料字段可写，写入 <script> 载荷后由受害者查看触发
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
POC 备注：仅文本工件，不执行。原草稿为离线静态证据，此处补充写入/读取/确认三步；写入点字段名需补充源码/路由确认，未确认前不得伪造请求。执行前将 TARGET 替换为授权测试实例。

## 4. 二次注入（SecondOrderAnalyzer）

本次未发现 store→read→sink 闭环的二次注入链。

## 5. AWVS 联动

- 输入模式：`zip`
- 导入结果：1 条
- 关联明细：1 条
- 目标种子：`awvs/targets.json`
- 说明：AWVS 是外部动态扫描器；本管线只导入其结果做佐证，或导出端点供 AWVS 播种。

| finding | AWVS | URL | 结论 |
|---|---|---|---|
| `LLM-be8d58eeb7fa` | Insecure Direct Object Reference | http://127.0.0.1:18081/008.php | corroborated |

## 6. 漏洞类型覆盖

| 类型 | CWE | AutoCVE | 本次数量 |
|---|---|---|---|
| `command_injection` | CWE-78 | 是 | 0 |
| `sql_injection` | CWE-89 | 是 | 3 |
| `blind_sql_injection` | CWE-89 |  | 0 |
| `ssrf` | CWE-918 | 是 | 0 |
| `path_traversal` | CWE-22 | 是 | 0 |
| `deserialization` | CWE-502 | 是 | 0 |
| `ssti` | CWE-1336 | 是 | 0 |
| `auth_bypass` | CWE-287 | 是 | 0 |
| `idor` | CWE-639 | 是 | 1 |
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
| safety_guard | 安全防护 | 4.33 | 是 |
| surface_mapper | 攻击面测绘 | 10.25 | 是 |
| deep_finder | LLM 深挖 | 11.7 | 是 |
| candidate_screener | 候选筛选 | 8.11 | 是 |
| vulnerability_analyzer | 漏洞分析 | 13.86 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 16.56 | 是 |
| coordinator | 管线协调 | 7.42 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
