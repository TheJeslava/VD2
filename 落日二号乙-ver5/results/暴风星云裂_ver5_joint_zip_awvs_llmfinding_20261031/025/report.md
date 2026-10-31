# 落日二号乙漏洞挖掘报告 — 20261031-214456-4ee232

- 生成时间：2026-10-31T13:45:51.724074+00:00
- 输入：`$WORKSPACE\暴风星云裂\025.zip`
- 输入模式：`zip`
- SHA256：`66af849b3e4604c64e51a3ebfe871ee7f6288606b9cdb1f87c1c6314d29cc49e`
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

本次汇总仅覆盖单文件 PHP 脚本 025.php（37 行），共交付 3 条 command_injection 发现，全部为 critical 且均带 POC：LLM-77434b11a59f（025.php 第 34 行附近，$_REQUEST['ip'] 经黑名单过滤后被 shell_exec 拼接执行，黑名单可绕过）、GEN-2da8a6e02c4e（第 26 行附近 Windows 分支 OS 命令注入）、GEN-eff51e7cd060（第 30 行附近 *nix 分支 OS 命令注入）。最高危即 025.php 的 ping 功能命令注入：请求参数与危险汇点在同一文件内近距离耦合，黑名单式过滤对 shell 元字符（如 ; | & $() 换行）覆盖不全，可直接导致任意命令执行。POC 齐全度为 3/3，但均为静态文本 POC（HTTP 形态），未做动态验证，不能宣称已复现。二次注入链：本次输入未提供任何二次注入链，故不涉及存储写点/读点/汇点三要素的判定。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 950 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 025.php（37 行），已逐行审计。确认存在一条闭合的命令注入链：$_REQUEST['ip']（025.php:5）经不完整黑名单 str_replace（025.php:8-21）后直接拼接进 shell_exec（025.php:26/30），输出回显于 025.php:34。黑名单未过滤换行符与单竖线，可稳定绕过。未发现数据库调用、文件包含、反序列化、SSRF、XSS 输出（$cmd 为命令输出非用户输入直出）等其他攻击面。weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 等配置类候选在文件中均无对应调用（无 md5/sha1、无 openssl/mcrypt、无 rand/mt_rand、无 setcookie、无 HTTP_X_FORWARDED_FOR 等），故不单独立项。未覆盖范围：无 php.ini/部署配置，无法确认 disable_functions、open_basedir 等对可利用性的影响；无路由/鉴权上下文，无法确认该脚本是否被前置鉴权保护。

未覆盖 / 证据缺口：
- 缺少 php.ini/disable_functions 配置，无法确认 shell_exec 是否可用
- 缺少部署与鉴权上下文，无法确认脚本是否公网可达或受前置鉴权保护
- 无其他文件，无法评估 include/依赖链

## 3. Findings

### F-1: 025.php ping 功能通过 $_REQUEST['ip'] 黑名单绕过导致命令注入（shell_exec）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.93`
- **结论**：`candidate` / 证据等级 `externally_corroborated`
- **位置**：`025.php:3-34`
- **来源**：`llm_finding`

**描述**

脚本在收到 POST 参数 Submit 后，从 $_REQUEST['ip'] 读取攻击者可控输入 $target，仅用 str_replace 做黑名单替换（移除 ||、&、;、'| '、-、$、(、)、`），随后直接拼接进 shell_exec('ping -c 4 ' . $target)（Windows 分支为 'ping  ' . $target）。黑名单存在多处缺陷：未过滤换行符 \n（shell 中作为命令分隔符）、未过滤 '|' 单字符（仅过滤了 '| ' 带空格形式）、未过滤 '>'、'<'、'#'、'\' 等；且 str_replace 为单次替换，可用 '||' 被替换为空后残留的构造或直接使用换行/单竖线绕过。攻击者可在 ping 目标后注入任意系统命令，以 Web 服务进程权限执行，导致服务器完全失陷。

**source / sink**

- source：body `ip`（025.php:5）
- sink：025.php:34 shell_exec('ping  -c 4 ' . $target) 与 shell_exec('ping  ' . $target)

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `025.php:3` | 检测到 POST 参数 Submit 存在，进入命令执行分支 | 请求进入处理逻辑 | 仅需提交 Submit 参数即可触发，无认证校验 |
| 2 | `025.php:5` | 从 $_REQUEST['ip'] 读取攻击者输入并 trim | $target = 攻击者原始字符串（去首尾空白） | $_REQUEST 同时接受 GET/POST/Cookie，输入面更宽 |
| 3 | `025.php:8-21` | 黑名单 str_replace 移除 \|\|、&、;、'\| '、-、$、(、)、` | $target 中上述子串被删除，但换行符 \n、单竖线 '\|'、'>'、'<'、'#' 等未被过滤 | 黑名单不完整：未过滤换行符（shell 命令分隔符）与单字符 '\|'；str_replace 单次替换可被构造绕过 |
| 4 | `025.php:30` | 过滤后的 $target 直接拼接进 shell_exec 执行 ping | 'ping  -c 4 ' . $target 作为 shell 命令字符串 | 无参数化、无 escapeshellarg/escapeshellcmd，直接交给 shell 解析 |
| 5 | `025.php:34` | 命令输出回显到页面 <pre> 中 | $cmd 为命令执行结果 | 攻击者可直接读取注入命令的输出 |

**POC**

针对 /025.php（POST）的 OS 命令注入 POC。注入点：POST 参数 Submit；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/025.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 OS 命令注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/025.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'Submit=%3Bid&Submit=Submit'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/LLM-77434b11a59f`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

未认证远程攻击者可在服务器上以 Web 进程权限执行任意系统命令，读取/篡改文件、横向移动，导致服务器完全失陷。

**CVE / CWE 论证**

CWE-78 OS 命令注入。外部 HTTP 可达、无需认证、source（$_REQUEST['ip']）到 sink（shell_exec）链路在 025.php 内完整闭合，黑名单可被换行符/单竖线绕过，命令输出直接回显，利用确定性高。

**修复建议**

不要将用户输入拼接进 shell 命令；改用 escapeshellarg() 对目标做严格转义，或使用白名单校验（仅允许合法 IP/主机名正则，如 filter_var($target, FILTER_VALIDATE_IP)），并避免使用 shell_exec 执行外部命令。

**验证说明**

需动态确认 shell_exec 未被 disable_functions 禁用、Web 进程权限，以及换行符/单竖线在目标 shell 下确实作为命令分隔符生效；本管线未执行 POC。
模型 POC 要点：利用黑名单未过滤换行符的缺陷，在 ip 参数中先给出合法 ping 目标，再用换行符分隔注入任意命令；也可用单竖线 '|' 绕过（黑名单只过滤了 '| ' 带空格形式）。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
AWVS 外部佐证：OS Command Injection @ http://127.0.0.1:18081/025.php（未在本管线执行扫描）。
PocWriter 建议（未采纳，缺少端点 /025.php）：针对 025.php（POST）的 OS 命令注入 POC。源码在 025.php:34 附近将外部输入拼接到系统命令执行调用中；本 POC 的注入通道为 POST 参数 Submit，payload 为 ;id，目标地址使用 TARGET 占位符。仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /025.php）：符合 CWE-78（OS 命令注入）。漏洞位于可交付代码 025.php:34，外部输入经 POST 参数 Submit 进入命令执行汇点，source→sink 链静态闭合且未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。request.http 中的 Content-Length 需按实际字节数校正；payload 中的 ; 已 URL 编码为 %3B。仅限授权测试。

**外部佐证**

- awvs: OS Command Injection @ http://127.0.0.1:18081/025.php

### F-2: 025.php Windows 分支 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`025.php:24-26`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入，该输入在 025.php:5 被读入变量 `target`，随后在 025.php:24 通过 `stristr(php_uname('s'),'Windows NT')` 判定为 Windows 平台后，于 025.php:26 直接拼接进 `shell_exec('ping  ' . $target)`。代码片段中未见任何转义（escapeshellarg/escapeshellcmd）、白名单校验或参数化处理，因此 `target` 中的 shell 元字符（如 `&`、`|`、`;`）会被 shell 解释，形成命令注入。

**source / sink**

- source：query `ip`（025.php:5）
- sink：025.php:26 $cmd = shell_exec( 'ping  ' . $target );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `025.php:5` | 从 query `ip` 读取外部输入 | 污点进入 target |  |
| 2 | `025.php:26` | 危险汇点：$cmd = shell_exec( 'ping  ' . $target ); | 污点进入 command_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /025（POST）的 OS 命令注入 POC。注入点：POST 参数 ip；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/025'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 OS 命令注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/025' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'ip=%3Bid&Submit=Submit'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/GEN-2da8a6e02c4e`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

远程命令执行：攻击者可在 Web 服务器进程权限下执行任意系统命令，导致服务器被完全控制、数据泄露、横向移动。无需认证（取决于部署，但代码本身无鉴权逻辑）。

**CVE / CWE 论证**

CWE-78（OS 命令注入）。外部可达：`ip` 为 HTTP 查询参数，直接由远程用户控制；无需认证；利用链闭合：source（025.php:5 query `ip`）→ 变量 `target` → sink（025.php:26 `shell_exec`），中间无有效净化。

**修复建议**

避免将用户输入拼接进 shell 命令；使用参数化方式（如 `escapeshellarg($target)` 并对 IP 做严格格式校验，仅允许合法 IP 字符集），或改用不经过 shell 的 API（如 `proc_open` 传数组参数）。同时对 `ip` 做白名单/正则校验（如 `filter_var($target, FILTER_VALIDATE_IP)`）。

**验证说明**

静态证据：入口 POST /025；source=query/ip；sink=025.php:26；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `025.php?ip=TARGET;id`（仅限授权测试）→ 025.php:5 读取 `ip` 到 `target` → 025.php:24 判定 Windows 平台 → 025.php:26 `shell_exec('ping  ' . $target)` 执行拼接后的命令，注入的 `;id` 被 shell 执行。
PocWriter 建议（未采纳，缺少端点 /025）：针对 025.php（POST）的 OS 命令注入 POC。源码在 025.php:26 附近将外部输入拼接到系统命令执行调用中；本 POC 的注入通道为 POST 参数 ip，payload 为 ;id，目标地址使用 TARGET 占位符。仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /025）：符合 CWE-78（OS 命令注入）。漏洞位于可交付代码 025.php:26，外部输入经 POST 参数 ip 进入命令执行汇点，source→sink 链静态闭合且未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。request.http 中的 Content-Length 需按实际字节数校正；payload 中的 ; 已 URL 编码为 %3B。仅限授权测试。

### F-3: 025.php *nix 分支 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`025.php:28-30`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入，该输入在 025.php:5 被读入变量 `target`，在 025.php:28 的非 Windows 分支中，于 025.php:30 直接拼接进 `shell_exec('ping  -c 4 ' . $target)`。代码片段中未见任何转义、白名单或参数化处理，`target` 中的 shell 元字符会被 shell 解释，形成命令注入。

**source / sink**

- source：query `ip`（025.php:5）
- sink：025.php:30 $cmd = shell_exec( 'ping  -c 4 ' . $target );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `025.php:5` | 从 query `ip` 读取外部输入 | 污点进入 target |  |
| 2 | `025.php:30` | 危险汇点：$cmd = shell_exec( 'ping  -c 4 ' . $target ); | 污点进入 command_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /025（POST）的 OS 命令注入 POC。注入点：POST 参数 ip；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/025'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 OS 命令注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/025' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'ip=%3Bid&Submit=Submit'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/GEN-eff51e7cd060`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

远程命令执行：攻击者可在 Web 服务器进程权限下执行任意系统命令，导致服务器被完全控制、数据泄露、横向移动。无需认证（取决于部署，但代码本身无鉴权逻辑）。

**CVE / CWE 论证**

CWE-78（OS 命令注入）。外部可达：`ip` 为 HTTP 查询参数，直接由远程用户控制；无需认证；利用链闭合：source（025.php:5 query `ip`）→ 变量 `target` → sink（025.php:30 `shell_exec`），中间无有效净化。

**修复建议**

避免将用户输入拼接进 shell 命令；使用 `escapeshellarg($target)` 并对 IP 做严格格式校验（如 `filter_var($target, FILTER_VALIDATE_IP)`），或改用 `proc_open` 传数组参数以避免 shell 解释。

**验证说明**

静态证据：入口 POST /025；source=query/ip；sink=025.php:30；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `025.php?ip=TARGET;id`（仅限授权测试）→ 025.php:5 读取 `ip` 到 `target` → 025.php:28 进入 *nix 分支 → 025.php:30 `shell_exec('ping  -c 4 ' . $target)` 执行拼接后的命令，注入的 `;id` 被 shell 执行。
PocWriter 建议（未采纳，缺少端点 /025）：针对 025.php（POST）的 OS 命令注入 POC。源码在 025.php:30 附近将外部输入拼接到系统命令执行调用中；本 POC 的注入通道为 POST 参数 ip，payload 为 ;id，目标地址使用 TARGET 占位符。仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /025）：符合 CWE-78（OS 命令注入）。漏洞位于可交付代码 025.php:30，外部输入经 POST 参数 ip 进入命令执行汇点，source→sink 链静态闭合且未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。request.http 中的 Content-Length 需按实际字节数校正；payload 中的 ; 已 URL 编码为 %3B。仅限授权测试。

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
| `LLM-77434b11a59f` | OS Command Injection | http://127.0.0.1:18081/025.php | corroborated |

## 6. 漏洞类型覆盖

| 类型 | CWE | AutoCVE | 本次数量 |
|---|---|---|---|
| `command_injection` | CWE-78 | 是 | 3 |
| `sql_injection` | CWE-89 | 是 | 0 |
| `blind_sql_injection` | CWE-89 |  | 0 |
| `ssrf` | CWE-918 | 是 | 0 |
| `path_traversal` | CWE-22 | 是 | 0 |
| `deserialization` | CWE-502 | 是 | 0 |
| `ssti` | CWE-1336 | 是 | 0 |
| `auth_bypass` | CWE-287 | 是 | 0 |
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
| safety_guard | 安全防护 | 3.67 | 是 |
| surface_mapper | 攻击面测绘 | 9.4 | 是 |
| deep_finder | LLM 深挖 | 11.06 | 是 |
| candidate_screener | 候选筛选 | 5.43 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.51 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 10.08 | 是 |
| coordinator | 管线协调 | 8.52 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
