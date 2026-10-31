# 落日二号乙漏洞挖掘报告 — 20261030-225228-d4eb7e

- 生成时间：2026-10-30T14:53:17.375482+00:00
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

本次汇总基于已去重的 2 条 LLM 发现，均为 high 级：一是 058_06.php 登录逻辑仅以客户端可伪造的 Auth Cookie 作为鉴权凭据，构成任意用户登录绕过（auth_bypass，行至 46）；二是 058_08.php 改密功能 UPDATE 语句拼接用户输入，作为二次注入的存储读点（sql_injection，行至 39）。两条均带 POC 文本（静态/HTTP 文本工件，未执行、未动态验证），POC 齐全度 2/2。最高危为 auth_bypass，因其直接突破鉴权边界。需注意：surface_notes 明确本次输入未提供源码片段，攻击面排序（058_05.php 双热点、058_08.php source 最多等）不构成漏洞结论，且 058_05.php 这一首要优先级区域未产出任何 finding，属未覆盖而非无风险。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：8 个文件 / 11823 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中全部 8 个 PHP 文件（058_01~058_08）。058_05.php 注册逻辑使用 mysql_escape_string 转义后拼接 INSERT，单次注入受转义限制；058_06.php 登录成功后仅下发明文 Auth=1 Cookie，而 058_01/04/08 仅以 isset($_COOKIE['Auth']) 鉴权，构成鉴权绕过（已报告）。058_08.php 改密 UPDATE 拼接 username（来自 session，源自 058_05 注册写点），存在二次注入链（已报告，置信度中等）。058_02/07 为纯静态表单页，无污点。058_03 为登录表单页。未覆盖：sql-connect.php 等 include 文件不在 code_pack，无法确认数据库字符集与连接配置；无认证/会话配置文件，鉴权边界仅按脚本推断。

未覆盖 / 证据缺口：
- sql-connections/sql-connect.php 未提供，无法确认字符集与 DB 权限
- 无 php.ini/Web 服务器配置，无法确认 display_errors 等
- 058_05.php 仅显示 1-66 行（共76行），尾部未覆盖
- 058_06.php 仅显示 1-59 行（共65行），尾部未覆盖
- 058_03.php 仅显示 1-38 行（共61行），058_04.php 仅显示 1-38 行（共91行），尾部未覆盖

## 3. Findings

### F-1: 058_06.php 登录逻辑使用客户端可伪造的 Auth Cookie 作为唯一鉴权凭据，导致任意用户登录绕过

- **类型**：`auth_bypass` / CWE-287
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`058_06.php:40-46`
- **来源**：`llm_finding`

**描述**

058_06.php 的 sqllogin() 在登录成功后仅设置 setcookie("Auth", 1, time()+3600)，而 058_01.php / 058_04.php / 058_08.php 的访问控制只检查 isset($_COOKIE["Auth"])，不校验其值、不校验签名、也不与 $_SESSION["username"] 绑定。攻击者无需任何凭据，直接手工设置 Cookie Auth=1 即可通过所有受保护页面的鉴权检查，访问 logged-in.php 等登录后功能（含 058_08.php 的改密功能）。这是典型的信任边界缺陷（CWE-565/CWE-807）：鉴权状态完全由客户端可控 Cookie 决定。

**source / sink**

- source：cookie `Auth`（058_06.php）
- sink：058_06.php:46 058_01.php:3 / 058_04.php:3 / 058_08.php:7 的 isset($_COOKIE["Auth"]) 鉴权判断

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_06.php:44` | 登录成功后服务端仅下发 Auth=1 的普通 Cookie，未签名、未与 session 绑定 | Auth=1 明文 Cookie |  |
| 2 | `058_01.php:3` | 受保护页面仅判断 isset($_COOKIE["Auth"])，不校验值来源 | 攻击者伪造的 Auth Cookie 被当作已认证 |  |
| 3 | `058_08.php:7` | 改密页面同样仅凭 Auth Cookie 存在即放行，进入改密逻辑 | 未认证攻击者获得改密页面访问权 |  |

**POC**

针对 058_06.php（POST /058_06.php）的认证绕过 POC。注入通道为 Cookie: Auth，payload 为 admin，目标地址统一使用 TARGET 占位符。POC 仅为文本工件，不执行、不联网。

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
- 执行状态：未执行（`executed=False`）

**影响**

任意未认证用户可绕过登录访问所有登录后功能，结合 058_08.php 改密逻辑可进一步尝试账户接管。

**CVE / CWE 论证**

CWE-565/CWE-807：鉴权依赖客户端可控 Cookie，外部无需认证即可触发，链闭合。

**修复建议**

鉴权只依赖服务端 $_SESSION，移除对 Auth Cookie 的信任；Cookie 若必须使用应加签名并设 HttpOnly/Secure。

**验证说明**

需确认部署环境中 058_04/058_08 是否确实以该 Cookie 作为唯一鉴权；session 是否另有校验。
模型 POC 要点：直接伪造 Auth Cookie 绕过登录访问受保护页面
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /058_06.php）：符合 CWE-287（认证不当）。漏洞位于 058_06.php:46，外部输入来自 Cookie Auth，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅限授权测试。保留原确定性 POC 的请求结构（POST /058_06.php，Cookie: Auth=admin）。目标地址一律使用 TARGET 占位符，禁止替换为真实 IP/域名。POC 为文本工件，管线不执行、不联网、不搭建沙箱。

### F-2: 058_08.php 改密功能 UPDATE 语句拼接用户输入（二次注入读点）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`058_08.php:31-39`
- **来源**：`llm_finding`

**描述**

058_08.php 的改密逻辑将 $_POST['password']、$_POST['re_password']、$_POST['current_password'] 经 mysql_real_escape_string 后直接拼入 UPDATE 语句。虽然单次请求做了转义，但 username 来自 $_SESSION["username"]，而该值在 058_05.php 注册时以 mysql_escape_string 转义后写入数据库（存储写点），注册时若使用宽字节/编码差异或转义函数不一致（mysql_escape_string 与 mysql_real_escape_string 行为不同），可形成二次注入。此处作为存储读点+危险汇点，需结合写点评估。

**source / sink**

- source：session `username`（058_08.php）
- sink：058_08.php:39 058_08.php:38 mysql_query($sql)

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `058_05.php:25` | 注册时 username 经 mysql_escape_string 转义后写入 users 表（存储写点） | 转义后的 username 落库 |  |
| 2 | `058_08.php:31` | 改密时从 $_SESSION 取出 username 作为查询条件（存储读点） | 从会话/库中取出的 username |  |
| 3 | `058_08.php:38` | username 拼入 UPDATE 语句执行（危险汇点） | 拼接进 SQL 的 username |  |

**POC**

针对 058_08.php（POST /058_08.php）的 SQL 注入 POC。注入点为 POST 参数 username，payload 为 ' OR '1'='1，目标地址统一使用 TARGET 占位符。POC 仅为文本工件，不执行、不联网。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/058_08.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/058_08.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-43e545c9bc6a`
- 执行状态：未执行（`executed=False`）

**影响**

可篡改 SQL 逻辑，绕过原密码校验修改任意账户密码，导致账户接管。

**CVE / CWE 论证**

CWE-89：二次注入，写点 058_05.php:25、读点 058_08.php:31、汇点 058_08.php:38 三者齐备。

**修复建议**

改用参数化查询（PDO/mysqli prepared statement），统一转义函数并设置正确字符集。

**验证说明**

需确认数据库字符集与 mysql_escape_string 的实际转义行为，验证宽字节注入可行性。
模型 POC 要点：通过注册阶段构造特殊 username，在改密阶段触发二次注入
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /058_08.php）：符合 CWE-89（SQL 注入）。漏洞位于 058_08.php:39，外部输入经 POST 参数 username 进入 SQL 查询汇点，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅限授权测试。保留原确定性 POC 的请求结构（POST /058_08.php，参数 username，payload ' OR '1'='1）。目标地址一律使用 TARGET 占位符，禁止替换为真实 IP/域名。POC 为文本工件，管线不执行、不联网、不搭建沙箱；SQL 注入不使用 DROP 等破坏性语句。

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
| safety_guard | 安全防护 | 4.28 | 是 |
| surface_mapper | 攻击面测绘 | 12.24 | 是 |
| deep_finder | LLM 深挖 | 11.83 | 是 |
| candidate_screener | 候选筛选 | 5.03 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 7.66 | 是 |
| coordinator | 管线协调 | 7.47 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
