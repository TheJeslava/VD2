# 落日二号乙漏洞挖掘报告 — 20261031-010201-95204e

- 生成时间：2026-10-30T17:02:48.841777+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\027.zip`
- 输入模式：`zip`
- SHA256：`0692e8f3bcf09553285200fdbb5eecd31f5db885c7d44a68982905afded500d3`
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

本次审计仅覆盖单文件 PHP 脚本 027.php（约 30 行），共交付 3 条 command_injection 发现，全部为 critical 且均带 POC：LLM-c9f36281b7cf（$_REQUEST['ip'] 拼接 shell_exec，黑名单可绕过，行 27）、GEN-2b40f95f1bb0（Windows 分支 ping 拼接，行 19）、GEN-c4599ae29817（*nix 分支 ping -c 4 拼接，行 23）。三者本质是同一处 ping 功能在不同分支/汇点上的重复呈现，最高危为 027.php 的 ping 参数直连 shell_exec 造成的未授权 RCE（若页面公网可达且无认证前置）。POC 齐全（3/3），但均为静态源码推导的 HTTP 型 POC 文本，未做动态验证。其余攻击面（路径穿越/文件包含、SQL 注入、XSS）与配置实现类（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）在本次输入中无候选，属未覆盖而非已排除。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 804 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 027.php（30 行），已逐行审计。确认一条完整闭合的高危链：$_REQUEST['ip']（第 5 行）→ 仅过滤 '&&' 与 ';' 的 str_replace 黑名单（第 8-14 行）→ shell_exec 拼接执行（第 19/23 行）→ 结果回显（第 27 行），构成未认证远程命令注入（CWE-78）。黑名单未覆盖 '\|'、'&'、反引号、$() 等元字符，可稳定绕过。未发现 SQL 查询、文件包含/路径操作、反序列化、SSRF、模板等其它汇点；文件中无 md5/sha1、无 setcookie/session、无加密调用，故 weak_hash/weak_crypto/weak_random/insecure_cookie 类候选无证据，不报告。未覆盖范围：无 php.ini/.htaccess/nginx.conf，无法确认 disable_functions 与实际 URL/访问控制；无部署与网络暴露信息。输入中未出现诱导性文本，无 prompt_injection 证据。

未覆盖 / 证据缺口：
- 无 php.ini 等配置，无法确认 shell_exec 是否被禁用
- 无路由/端点清单，无法确认实际 URL 与是否需登录
- 无部署与网络暴露信息，无法评估公网可达性
- 无数据库/外部服务配置，SQL 注入面不存在于本文件

## 3. Findings

### F-1: 027.php ping 功能通过 $_REQUEST['ip'] 拼接 shell_exec 导致命令注入（黑名单可绕过）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`027.php:3-27`
- **来源**：`llm_finding`

**描述**

027.php 在收到 POST 参数 Submit 后，从 $_REQUEST['ip'] 读取用户输入 $target（第 5 行），仅用 str_replace 删除 '&&' 与 ';' 两个子串（第 8-14 行）作为黑名单，随后直接把 $target 拼接到 shell_exec('ping -c 4 ' . $target)（*nix，第 23 行）或 shell_exec('ping ' . $target)（Windows，第 19 行）执行。黑名单只过滤 '&&' 和 ';'，未过滤管道符 '|'、后台执行 '&'、命令替换反引号、$()、换行等 shell 元字符，也未使用 escapeshellarg/escapeshellcmd，因此攻击者可在 ip 参数中注入任意系统命令，实现远程命令执行。

**source / sink**

- source：body `ip`（027.php:5）
- sink：027.php:27 shell_exec('ping -c 4 ' . $target)（第 23 行）/ shell_exec('ping ' . $target)（第 19 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `027.php:3` | 检查 POST 参数 Submit 是否存在，作为进入处理逻辑的开关 | 请求进入分支 |  |
| 2 | `027.php:5` | 从 $_REQUEST['ip'] 读取攻击者可控输入并赋给 $target | $target = 攻击者原始字符串 | $_REQUEST 同时接受 GET/POST/Cookie，无类型或白名单校验 |
| 3 | `027.php:8-14` | 用 str_replace 删除 '&&' 与 ';' 两个子串 | $target 中 '&&' 与 ';' 被移除，其余字符原样保留 | 黑名单仅覆盖 '&&' 与 ';'，未过滤 '\|'、'&'、'`'、'$()'、换行等 shell 元字符，可用管道符或命令替换绕过 |
| 4 | `027.php:23` | 将未净化的 $target 拼接到 ping 命令并交给 shell_exec 执行 | 'ping -c 4 ' + $target 作为 shell 命令字符串执行 | 未使用 escapeshellarg/escapeshellcmd，shell 会解释注入的元字符 |
| 5 | `027.php:27` | 命令输出回显到页面 <pre> 中，攻击者可直接读取执行结果 | $cmd 为命令 stdout，拼入 $html 输出 |  |

**POC**

针对 /027.php（POST）的 OS 命令注入 POC。注入点：POST 参数 ip；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/027.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 OS 命令注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/027.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'ip=%3Bid'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/LLM-c9f36281b7cf`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

未认证远程攻击者可在服务器上以 Web 服务进程权限执行任意系统命令，读取敏感文件、横向移动、植入后门，完全控制主机。

**CVE / CWE 论证**

CWE-78 OS 命令注入。外部 HTTP 参数 ip 直接拼接进 shell_exec，黑名单仅过滤 '&&' 与 ';'，可用 '|' 等元字符绕过，source→sink 链在 CODE PACK 内完整闭合，无需认证。

**修复建议**

不要将用户输入拼接进 shell 命令；改用 escapeshellarg($target) 对参数整体转义，或使用白名单校验 IP 格式（filter_var($target, FILTER_VALIDATE_IP)），并避免使用 shell_exec 执行外部命令。

**验证说明**

需动态确认 shell_exec 未被 disable_functions 禁用、目标 OS 分支（*nix 使用 -c 4）以及 Web 进程权限；POC 仅限授权测试。
模型 POC 要点：向 027.php 提交 ip 参数，利用管道符 '|' 绕过仅过滤 '&&' 与 ';' 的黑名单，在 ping 命令后追加任意系统命令，并从回显的 <pre> 中读取结果。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /027.php）：针对 027.php 第 27 行（POST 入口）的 OS 命令注入 POC。注入点为 POST 表单参数 ip，其值被拼接进系统命令执行；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /027.php）：符合 CWE-78（OS 命令注入）。漏洞位于可交付代码 027.php:27，外部输入来自 POST body 参数 ip，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。使用前将 TARGET 替换为授权测试目标；payload 中 ; 需 URL 编码为 %3B。建议先做基线对比再判定。

### F-2: 027.php Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`027.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP query 参数 `ip` 提供输入，027.php:5 将其读入 `$target`；027.php:17 用 `stristr(php_uname('s'),'Windows NT')` 判断运行平台，命中 Windows 分支后，027.php:19 执行 `$cmd = shell_exec( 'ping  ' . $target );`，把 `$target` 直接字符串拼接到 shell 命令中。代码未对 `$target` 做任何白名单校验、转义（如 escapeshellarg）或参数化，因此 `ip` 中的 shell 元字符（`&`、`|`、`;`、`&&` 等）会被 shell 解释，形成命令注入。该分支仅在 Windows 主机上触发，属于平台相关但外部可达的注入点。

**source / sink**

- source：query `ip`（027.php:5）
- sink：027.php:19 $cmd = shell_exec( 'ping  ' . $target );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `027.php:5` | 从 query `ip` 读取外部输入 | 污点进入 target |  |
| 2 | `027.php:19` | 危险汇点：$cmd = shell_exec( 'ping  ' . $target ); | 污点进入 command_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /027（ANY）的 OS 命令注入 POC。注入点：ANY 参数 ip；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/027'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 OS 命令注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/027?ip=%3Bid'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/GEN-2b40f95f1bb0`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

远程未认证攻击者可在 Web 服务进程权限下执行任意系统命令，导致服务器完全失陷（RCE）、敏感文件读取、内网横向移动与持久化。

**CVE / CWE 论证**

CWE-78（OS Command Injection）。外部可达性：注入点位于 HTTP query 参数 `ip`，无需认证即可访问；利用链闭合：`ip` → `$target`（027.php:5）→ `shell_exec('ping  ' . $target)`（027.php:19），中间无有效净化；触发条件为 Windows 平台（027.php:17 分支），在目标为 Windows 时无需额外前置条件。

**修复建议**

不要用字符串拼接构造 shell 命令：改用参数数组形式（如 `proc_open`/`exec` 传入参数数组）或 PHP 的 `escapeshellarg($target)`/`escapeshellcmd` 组合；同时对 `ip` 做严格白名单校验（仅允许 IPv4/IPv6 字面量，如 `filter_var($target, FILTER_VALIDATE_IP)`），拒绝含空白与 shell 元字符的输入；以最小权限账户运行 Web 服务。

**验证说明**

静态证据：入口 ANY /027；source=query/ip；sink=027.php:19；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `027.php?ip=TARGET注入载荷` → 027.php:5 读取 query `ip` 到 `$target` → 027.php:17 平台判断进入 Windows 分支 → 027.php:19 `shell_exec('ping  ' . $target)` 拼接执行，注入的命令随 ping 一并被 shell 执行。
PocWriter 建议（未采纳，缺少端点 /027）：针对 027.php 第 19 行（ANY 入口）的 OS 命令注入 POC。注入点为查询参数 ip，其值被拼接进系统命令执行；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /027）：符合 CWE-78（OS 命令注入）。漏洞位于可交付代码 027.php:19，外部输入来自 query 参数 ip，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。使用前将 TARGET 替换为授权测试目标；payload 中 ; 需 URL 编码为 %3B。ANY 方法建议实际以 GET 发送。

### F-3: 027.php *nix 分支 ping -c 4 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`027.php:21-23`
- **来源**：`rule`

**描述**

攻击者通过 HTTP query 参数 `ip` 提供输入，027.php:5 将其读入 `$target`；当 027.php:17 的平台判断不成立（非 Windows，即 *nix 分支）时，027.php:23 执行 `$cmd = shell_exec( 'ping  -c 4 ' . $target );`，把 `$target` 直接拼接到 shell 命令。代码未对 `$target` 做白名单校验或 `escapeshellarg` 转义，`ip` 中的 `;`、`|`、`&&`、`$()`、反引号等元字符会被 shell 解释，构成命令注入。该分支在 Linux/Unix 主机上默认触发，是主要利用路径。

**source / sink**

- source：query `ip`（027.php:5）
- sink：027.php:23 $cmd = shell_exec( 'ping  -c 4 ' . $target );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `027.php:5` | 从 query `ip` 读取外部输入 | 污点进入 target |  |
| 2 | `027.php:23` | 危险汇点：$cmd = shell_exec( 'ping  -c 4 ' . $target ); | 污点进入 command_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /027（ANY）的 OS 命令注入 POC。注入点：ANY 参数 ip；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/027'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 OS 命令注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/027?ip=%3Bid'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/GEN-c4599ae29817`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

远程未认证攻击者可在 Web 服务进程权限下执行任意系统命令，实现 RCE、读取任意文件、窃取凭据、建立持久化后门，并可作为内网跳板。

**CVE / CWE 论证**

CWE-78（OS Command Injection）。外部可达性：注入点为 HTTP query 参数 `ip`，无需认证；利用链闭合：`ip` → `$target`（027.php:5）→ `shell_exec('ping  -c 4 ' . $target)`（027.php:23），无有效净化；在 *nix 平台（027.php:21 分支）默认可达，无需额外前置条件。

**修复建议**

改用参数数组方式执行外部程序（`proc_open`/`exec` 传数组，避免经 shell 解析）；若必须拼接，使用 `escapeshellarg($target)`；并对 `ip` 做严格白名单（`filter_var($target, FILTER_VALIDATE_IP)` 仅接受合法 IP 字面量），拒绝空白与 shell 元字符；以最小权限运行服务并限制出站命令执行能力。

**验证说明**

静态证据：入口 ANY /027；source=query/ip；sink=027.php:23；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `027.php?ip=TARGET注入载荷` → 027.php:5 读取 query `ip` 到 `$target` → 027.php:17 平台判断不成立进入 *nix 分支（027.php:21）→ 027.php:23 `shell_exec('ping  -c 4 ' . $target)` 拼接执行，注入命令被 shell 执行。
PocWriter 建议（未采纳，缺少端点 /027）：针对 027.php 第 23 行（ANY 入口）的 OS 命令注入 POC。注入点为查询参数 ip，其值被拼接进系统命令执行；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /027）：符合 CWE-78（OS 命令注入）。漏洞位于可交付代码 027.php:23，外部输入来自 query 参数 ip，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。使用前将 TARGET 替换为授权测试目标；payload 中 ; 需 URL 编码为 %3B。ANY 方法建议实际以 GET 发送。

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
| `command_injection` | CWE-78 | 是 | 3 |
| `sql_injection` | CWE-89 | 是 | 0 |
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
| safety_guard | 安全防护 | 2.31 | 是 |
| surface_mapper | 攻击面测绘 | 10.15 | 是 |
| deep_finder | LLM 深挖 | 9.54 | 是 |
| candidate_screener | 候选筛选 | 4.18 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.39 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.92 | 是 |
| coordinator | 管线协调 | 6.14 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
