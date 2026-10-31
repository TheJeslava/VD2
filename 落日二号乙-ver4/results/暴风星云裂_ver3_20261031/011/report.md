# 落日二号乙漏洞挖掘报告 — 20261031-005811-d98518

- 生成时间：2026-10-30T16:59:11.264960+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\011.zip`
- 输入模式：`zip`
- SHA256：`3a159dc6461698f5f7e43da6633e753a69f633ebb87ffaf30a0c927910d78d0e`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总基于单文件 PHP 项目 011.php（32 行）的已去重 findings，共 4 条，全部带 POC（4/4）。最高危为 LLM-c969ca7950b6：011.php 第 3 行读取的 username 参数在第 13 行附近直接拼接进 SQL，构成认证绕过式 SQL 注入（critical，HTTP POC 可复现）。其余为：登录接口缺少暴力破解防护（high，HTTP POC）、登录成功页 username 原样回显导致反射型 XSS（medium，HTTP POC）、以及口令使用 MD5 的弱哈希问题（medium，仅静态证据 POC，不能宣称可动态复现）。需注意 SEM-2ea8df0ef3b9 标题写 weak_crypto，但描述为 MD5/CWE-328，按类型规范应归为 weak_hash，建议人工校正类型标签。所有结论均为源码级推断，未做动态验证。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1212 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 011.php（32 行，全量可见）。已审计：GET 参数读取（第 3/5/8 行）、SQL 拼接与执行（第 12-13 行）、结果处理与登录判定（第 15-17 行）、HTML 输出（第 21-22 行）、连接关闭（第 29 行）。确认两条闭合链：username 参数 SQL 注入（可认证绕过，critical）与登录成功页 username 反射型 XSS（medium）。password 经 md5() 后为固定十六进制，不构成注入点；md5 用于口令哈希属 weak_hash 线索，但缺少注册/存储侧代码，无法确认是否安全敏感场景，未单独立项。未发现命令执行、文件操作、SSRF、反序列化、模板注入等汇点。未覆盖：无 php.ini/Web 服务器配置、无路由与认证元数据、无数据库 schema、无依赖清单，故 SQL 注入的实际表结构与 XSS 的 CSP 情况需动态确认。

未覆盖 / 证据缺口：
- 无 php.ini/.htaccess/nginx 配置，无法确认 allow_url_include、display_errors 等
- 无端点/路由清单，无法确认访问路径与是否需要认证
- 无数据库 schema，SQL 注入的表/列结构为推断
- 无 composer 依赖清单
- md5 口令哈希的存储与使用场景未提供，weak_hash 未闭合

## 3. Findings

### F-1: 011.php 登录处 username 参数直接拼接进 SQL 导致认证绕过式 SQL 注入

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`011.php:5-13`
- **来源**：`llm_finding`

**描述**

011.php 第 3 行判断 $_GET['Login'] 存在后，第 5 行直接读取 $_GET['username'] 到 $user，未做任何转义/参数化；第 12 行将 $user 以单引号包裹拼进 SELECT 语句，第 13 行交给 mysqli_query 执行。攻击者可通过 username 注入恒真条件（如 ' OR '1'='1' -- -）绕过密码校验，返回 users 表首行，从而以任意/首个用户身份登录受保护区域；也可用 UNION/布尔/报错注入读取任意数据库内容。password 虽经 md5() 处理（第 9 行），但 md5 输出为固定 32 位十六进制，无法注入，因此注入点唯一在 username。

**source / sink**

- source：query `username`（011.php）
- sink：011.php:13 mysqli_query($GLOBALS["___mysqli_ston"], $query)（011.php:13）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:3` | 判断 $_GET['Login'] 是否存在，决定进入登录分支 | 攻击者控制请求参数存在性 |  |
| 2 | `011.php:5` | 将 $_GET['username'] 原样赋给 $user，无任何过滤/转义 | 原始攻击者字符串 |  |
| 3 | `011.php:12` | $user 被单引号包裹拼入 SQL 语句，未使用预处理或 mysqli_real_escape_string | 注入 payload 进入 SQL 语法层 | 无参数化、无转义、无白名单，单引号可直接闭合字符串字面量 |
| 4 | `011.php:13` | 拼接后的语句交给 mysqli_query 执行 | 恶意 SQL 被执行 |  |
| 5 | `011.php:15` | mysqli_num_rows($result)==1 成立即视为登录成功，输出欢迎信息与 avatar | 认证被绕过，进入受保护区域 |  |

**POC**

针对 /011.php（GET）的 SQL 注入 POC。注入点：GET 参数 username（源码 011.php:13 将外部输入拼入 SQL 查询）；payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/011.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/011.php?username=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-c969ca7950b6`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

未授权绕过登录进入受保护区域；可进一步通过 UNION/布尔/报错注入读取 users 表及其它数据库数据，导致账户凭据泄露与数据库整体失陷。

**CVE / CWE 论证**

CWE-89 SQL 注入。外部 GET 参数 username 直达 mysqli_query，无认证前置、无参数化，利用链在单文件内完全闭合，属典型可申报 CVE 的注入。

**修复建议**

改用预处理语句（mysqli_prepare + bind_param）绑定 username/password；对输入做类型与长度校验；避免将用户输入拼接进 SQL；错误信息不要回显数据库错误。

**验证说明**

需动态确认 users 表存在且至少一行、mysqli 连接可用；确认部署未在 Web 层额外拦截单引号。源码层面注入链已闭合。
模型 POC 要点：利用 username 注入恒真条件绕过密码校验，实现未授权登录
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /011.php）：符合 CWE-89。漏洞位于可交付代码 011.php:13，外部输入来自 query 参数 username，source→sink 链已静态闭合，未发现有效净化；具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构；poc.sh 仅为文本，需人工替换 TARGET 后手动执行，禁止自动执行或联网。

### F-2: 011.php 登录接口缺少暴力破解防护（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`011.php:2-3`
- **来源**：`rule`

**描述**

011.php:3 以 if(isset($_GET['Login'])) 进入登录流程，读取 username/password 并查询数据库，但整个文件中未见失败计数、账号锁定、验证码、延迟或速率限制逻辑。攻击者可对同一接口无限次提交口令猜测。

**source / sink**

- source：request `login/password`（011.php）
- sink：011.php:3 if( isset( $_GET[ 'Login' ] ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:3` | 登录流程未见失败计数、锁定或速率限制；需授权环境重复请求确认 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /011（ANY）的 暴力破解防护缺失 POC。注入点：ANY 参数 login/password；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/011'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 暴力破解防护缺失 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/011?login/password=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-bb3630458a80`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可对已知或枚举出的用户名进行在线口令爆破/撞库，最终获得账号访问权限；结合 011.php:9 的 MD5 无盐哈希，一旦数据库泄露还可离线加速破解。

**CVE / CWE 论证**

CWE-307（对过量认证尝试缺乏防护）。外部可达性：011.php:3 的登录分支无需认证即可反复调用；利用链为重复请求 → 每次均执行 011.php:12/13 的查询与比对，无任何计数或锁定阻断。需说明：本项为语义模式命中，实际可利用性依赖部署环境是否存在前置 WAF/限流，属推断。

**修复建议**

引入失败计数与账号/IP 维度锁定（如 5 次失败锁定 15 分钟）；增加验证码或渐进延迟；记录并告警异常登录；统一失败提示避免用户名枚举；配合强哈希（password_hash）降低离线破解收益。

**验证说明**

静态证据：入口 ANY /011；source=request/login/password；sink=011.php:3；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者脚本循环请求 011.php?Login=1&username=admin&password=<猜测>，011.php:3 每次进入登录逻辑，011.php:12/13 执行查询并返回结果，因无失败计数与锁定，可持续猜测直至命中。
PocWriter 建议（未采纳，缺少端点 /011）：暴力破解防护缺失 POC（CWE-307）。源码 011.php:3 附近涉及登录/口令处理，未发现速率限制或锁定机制。注意：输入给出的注入点写法 `login/password` 不是合法 HTTP 参数名，需按实际源码中的参数名（如 username/password）构造请求；此处保留原结构并标注需人工核对参数名。仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /011）：符合 CWE-307。漏洞位于可交付代码 011.php:3 附近，缺少失败计数/限速/锁定逻辑；需结合部署确认可利用性。
POC 备注：原 POC 中 `login/password` 参数名不合法，已改为 username/password 示例并标注需人工核对；poc.sh 仅为文本，禁止自动执行或联网。

### F-3: 011.php 使用 MD5 处理口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`011.php:8-9`
- **来源**：`rule`

**描述**

011.php:8 从 $_GET['password'] 取得明文口令，011.php:9 直接 $pass = md5($pass) 后用于 011.php:12 的登录比对。MD5 为快速、无盐、已被证明存在碰撞的哈希算法，用于口令存储/校验属弱哈希。注意：该弱点本质是 weak_hash（CWE-328），而非 weak_crypto（CWE-327，指 DES/ECB 等加密算法误用）。

**source / sink**

- source：repository `md5(`（011.php）
- sink：011.php:9 	$pass = md5( $pass );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:9` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：011.php:9 使用 md5() 对用户口令做哈希（011.php:8 从 $_GET['password'] 取值）。MD5 属弱哈希算法，应归类为 weak_hash（CWE-328），而非 weak_crypto（CWE-327）；此处按输入给定的 weak_crypto 类型记录，但需在评审中修正分类。无需发送请求。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 011.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-2ea8df0ef3b9`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

若数据库泄露，攻击者可用彩虹表/GPU 高速爆破在极短时间内还原用户明文口令；无盐设计使相同口令产生相同哈希，便于批量破解与撞库，进而横向接管账号。

**CVE / CWE 论证**

CWE-328（使用弱哈希算法）。属实现型弱点，无需 HTTP 污点链即可成立：算法名 md5( 在 011.php:9 有原文证据，保护对象为登录口令（011.php:8 的 password 参数）。外部可达性：登录接口无需认证即可触发哈希计算路径。

**修复建议**

改用 password_hash($pass, PASSWORD_DEFAULT)（bcrypt/Argon2）存储，校验用 password_verify()；为每个口令使用独立随机盐（password_hash 已内置）；对历史 MD5 数据在用户下次登录时透明升级；禁止在日志或错误信息中输出哈希。

**验证说明**

静态证据：入口 ANY /011；source=repository/md5(；sink=011.php:9；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交 password → 011.php:8 赋值 → 011.php:9 md5() 生成无盐哈希 → 011.php:12 拼入查询比对。攻击者获取数据库后对 32 位 MD5 值做字典/彩虹表攻击即可还原口令。
POC 备注：纯静态证据，无网络请求；poc_readme.md 仅记录文件与行号片段，不执行。

### F-4: 011.php 登录成功页将 username 原样回显导致反射型 XSS

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`011.php:5-21`
- **来源**：`llm_finding`

**描述**

第 21 行将 $user（来自 $_GET['username']，第 5 行）直接拼入 HTML 输出 "<p>Welcome to the password protected area {$user}</p>"，未做 htmlspecialchars 等编码。虽然该分支需登录成功才触发，但结合同文件 SQL 注入（username 恒真注入）可让攻击者构造同时满足注入与脚本注入的 payload，使页面回显攻击者脚本，构成反射型 XSS。

**source / sink**

- source：query `username`（011.php:5）
- sink：011.php:21 $html 拼接输出（011.php:21）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:5` | 读取 $_GET['username'] 到 $user，无编码 | 原始攻击者字符串 |  |
| 2 | `011.php:21` | $user 直接插入 HTML 段落，未 htmlspecialchars | 脚本标签进入响应 HTML | 无输出编码 |
| 3 | `011.php:22` | $html 最终输出到响应（结合 avatar 输出） | 浏览器解析执行脚本 |  |

**POC**

针对 /011.php（GET）的反射型 XSS POC。注入点：GET 参数 username（源码 011.php:21 将外部输入输出到响应且未编码）；payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/011.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/011.php?username=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-cdf654069098`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可在受害者浏览器执行任意脚本，窃取会话/发起 CSRF 操作；结合注入可扩大影响。

**CVE / CWE 论证**

CWE-79 反射型 XSS。username 从 GET 直达 HTML 输出无编码，链闭合；但触发依赖登录成功分支，故定级 medium。

**修复建议**

输出前对 $user 使用 htmlspecialchars($user, ENT_QUOTES, 'UTF-8')；对 avatar 等数据库字段同样做输出编码与 URL 校验。

**验证说明**

需确认登录成功分支可达（依赖 SQL 注入或合法凭据）；确认响应未设置 CSP 或其它输出过滤。
模型 POC 要点：构造同时通过 SQL 校验并携带脚本的 username，触发反射型 XSS
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /011.php）：符合 CWE-79。漏洞位于可交付代码 011.php:21，外部输入来自 query 参数 username，source→sink 链已静态闭合，未发现有效净化；具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构；poc.sh 仅为文本，需人工替换 TARGET 后手动执行，禁止自动执行或联网。

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
| `weak_crypto` | CWE-327 |  | 1 |
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
| `brute_force` | CWE-307 |  | 1 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.0 | 是 |
| surface_mapper | 攻击面测绘 | 9.03 | 是 |
| deep_finder | LLM 深挖 | 12.04 | 是 |
| candidate_screener | 候选筛选 | 6.64 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.11 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 12.44 | 是 |
| coordinator | 管线协调 | 6.27 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
