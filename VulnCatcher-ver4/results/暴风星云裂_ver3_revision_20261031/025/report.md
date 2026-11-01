# 落日二号乙漏洞挖掘报告 — 20261031-011819-945603

- 生成时间：2026-10-30T17:19:03.652664+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\025.zip`
- 输入模式：`zip`
- SHA256：`66af849b3e4604c64e51a3ebfe871ee7f6288606b9cdb1f87c1c6314d29cc49e`
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

本次汇总基于已去重的 3 条 findings，全部集中在单文件 PHP 脚本 025.php，类型均为 command_injection（CWE-78），严重度 critical，且 3 条均带 POC（HTTP 型，可对 TARGET 的 ip 参数注入）。最高危的是 LLM-77434b11a59f：025.php 第 34 行附近 ping 功能通过 ip 参数拼接进系统命令，且存在黑名单过滤但可绕过，属于可直接命令执行的高危点；GEN-2da8a6e02c4e（第 26 行 Windows 分支）与 GEN-eff51e7cd060（第 30 行 *nix 分支）是同一污点链在不同平台分支上的规则命中，三者本质为同一处命令拼接缺陷的多分支表现，建议合并修复（改用参数数组/白名单校验）。POC 齐全度为 3/3，但均为静态构造的 HTTP POC 文本，未做动态验证。本次无二次注入链、无配置型候选交付。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 950 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 025.php（37 行，完整展示）。发现 1 个闭合的命令注入链：$_REQUEST['ip'] → 不完整黑名单 str_replace → shell_exec 拼接执行，可绕过黑名单实现 RCE。未发现 SQL 注入、文件包含、XSS（输出为命令结果非直接参数回显）、弱加密/弱随机/不安全 Cookie 等其它线索；输入未提供部署配置、认证层与路由信息，无法评估 trust_boundary 与可达性。

未覆盖 / 证据缺口：
- 缺少 Web 服务器与 php.ini 配置，无法确认 shell_exec 是否被禁用及 allow_url_include 等
- 无路由/认证配置，无法确认该脚本是否暴露于未认证边界
- 无依赖清单，无法评估第三方组件 CVE

## 3. Findings

### F-1: 025.php ping 功能通过 ip 参数导致命令注入（黑名单可绕过）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`025.php:3-34`
- **来源**：`llm_finding`

**描述**

脚本在 $_POST['Submit'] 存在时读取 $_REQUEST['ip']，仅用 str_replace 删除黑名单字符（||、&、;、'| '、-、$、(、)、`），随后直接拼接到 shell_exec('ping -c 4 ' . $target)（Windows 分支为 'ping ' . $target）。黑名单不完整：换行符 \n、制表符、以及 '|' 后跟非空格字符（如 '|id'）均未被过滤，且 str_replace 只做一次替换，可用 '||' 变形或换行绕过。攻击者可在 ip 参数中注入任意系统命令，以 Web 服务器权限执行，导致完全 RCE。

**source / sink**

- source：body `ip`（025.php:5）
- sink：025.php:34 shell_exec('ping -c 4 ' . $target) 与 shell_exec('ping ' . $target)

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `025.php:3` | 检查 $_POST['Submit'] 是否存在，作为进入处理逻辑的开关 | 请求进入处理分支 |  |
| 2 | `025.php:5` | 从 $_REQUEST['ip'] 读取攻击者可控输入并 trim | $target = 攻击者原始输入 |  |
| 3 | `025.php:8-18` | 定义黑名单替换数组，仅覆盖部分 shell 元字符 | 黑名单集合 |  |
| 4 | `025.php:21` | str_replace 单次替换删除黑名单字符 | $target 被过滤，但换行、制表符、'\|' 后接非空格字符等未被移除 | 黑名单不完整且 str_replace 只做一次替换，'\|' 仅在后面跟空格时被删，'\|id' 或换行注入可绕过 |
| 5 | `025.php:30` | 将过滤后的 $target 直接拼接到 shell_exec 命令字符串 | 命令字符串 'ping -c 4 ' . $target 含注入内容 |  |
| 6 | `025.php:30` | shell_exec 执行拼接后的命令，返回输出 | 系统命令执行结果写入 $cmd |  |
| 7 | `025.php:34` | 命令输出回显到页面 <pre> 标签 | $cmd 输出展示给攻击者 |  |

**POC**

针对 /025.php（POST）的 OS 命令注入 POC。注入点：POST 参数 ip；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/025.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 OS 命令注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/025.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'ip=%3Bid'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/LLM-77434b11a59f`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

未认证远程攻击者可在目标服务器上以 Web 服务器进程权限执行任意系统命令，完全控制服务器（RCE）。

**CVE / CWE 论证**

CWE-78 OS 命令注入。source（$_REQUEST['ip']）到 sink（shell_exec）链路完整，黑名单可绕过，无需认证即可从外部触发，符合 CVE 申报条件。

**修复建议**

不要将用户输入拼接到 shell 命令。使用 escapeshellarg() 对 $target 转义，或使用白名单校验 IP 格式（filter_var($target, FILTER_VALIDATE_IP)），并避免使用 shell_exec 拼接。

**验证说明**

需动态确认目标 OS 分支及 shell_exec 是否被禁用（disable_functions），以及 Web 用户权限；源码层面链路已闭合。
模型 POC 要点：向 025.php 提交 ip 参数，利用未被过滤的换行符或 '|' 后接非空格字符注入任意命令，命令输出通过 shell_exec 回显。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /025.php）：针对 025.php 第 34 行 OS 命令注入的 POC。外部输入来自 POST body 参数 ip，未净化即拼入系统命令执行 sink，可导致任意命令执行（CWE-78）。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /025.php）：符合 CWE-78（OS 命令注入）。漏洞位于 025.php:34，外部输入来自 POST body 参数 ip，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。脚本中的 TARGET 需由授权测试人员手动替换；禁止用于未授权目标。

### F-2: 025.php Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`025.php:24-26`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入，该输入在 025.php:5 被读入变量 `target`。代码在 025.php:24 用 `stristr(php_uname('s'), 'Windows NT')` 判断运行平台，命中 Windows 分支后，在 025.php:26 执行 `$cmd = shell_exec( 'ping  ' . $target );`。`target` 未经任何转义、白名单校验或参数化处理，直接以字符串拼接方式进入 `shell_exec`，因此 `&`、`|`、`;`、`&&` 等 shell 元字符会被解释为命令分隔符，攻击者可追加任意系统命令。该分支仅在 Windows 主机上触发，属于平台相关的利用条件，但一旦命中即无需认证、外部可达。

**source / sink**

- source：query `ip`（025.php:5）
- sink：025.php:26 $cmd = shell_exec( 'ping  ' . $target );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `025.php:5` | 从 query `ip` 读取外部输入 | 污点进入 target |  |
| 2 | `025.php:26` | 危险汇点：$cmd = shell_exec( 'ping  ' . $target ); | 污点进入 command_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /025（ANY）的 OS 命令注入 POC。注入点：ANY 参数 ip；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/025'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 OS 命令注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/025?ip=%3Bid'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/GEN-2da8a6e02c4e`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

远程未认证攻击者可在 Web 服务进程权限下执行任意操作系统命令，导致服务器完全失陷（RCE）、读取/篡改应用与系统文件、横向移动。Windows 分支下可执行 `ip=127.0.0.1 & whoami` 之类的命令。

**CVE / CWE 论证**

CWE-78（OS Command Injection）：外部可控的查询参数 `ip` 经变量 `target` 未净化拼接进 `shell_exec`，构成 source→sink 闭合链；入口为公开 HTTP 端点，无需认证，攻击者仅需构造 query 即可触发，外部可达性成立。利用条件为运行在 Windows NT 平台（025.php:24 判断），属环境前提而非额外权限要求。

**修复建议**

不要用字符串拼接构造 shell 命令。优先使用参数数组形式（如 `proc_open`/`escapeshellarg` 配合固定命令），或改用不经过 shell 的库/函数执行 ping；对 `ip` 参数做严格白名单校验（仅允许 IPv4/IPv6 字面量，用 `filter_var($ip, FILTER_VALIDATE_IP)` 校验），校验失败直接拒绝；以最小权限账户运行 Web 服务，禁用不必要的 shell 执行能力。

**验证说明**

静态证据：入口 ANY /025；source=query/ip；sink=025.php:26；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：HTTP 请求 `?ip=<payload>` → 025.php:5 读取 query `ip` 到 `target` → 025.php:24 平台判断命中 Windows 分支 → 025.php:26 `shell_exec('ping  ' . $target)` 拼接执行 → shell 解释 payload 中的元字符 → 任意命令执行。
PocWriter 建议（未采纳，缺少端点 /025）：针对 025.php 第 26 行 OS 命令注入的 POC。外部输入来自 query 参数 ip，未净化即拼入系统命令执行 sink，可导致任意命令执行（CWE-78）。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /025）：符合 CWE-78（OS 命令注入）。漏洞位于 025.php:26，外部输入来自 query 参数 ip，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。脚本中的 TARGET 需由授权测试人员手动替换；禁止用于未授权目标。

### F-3: 025.php *nix 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`025.php:28-30`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入，该输入在 025.php:5 被读入变量 `target`。当 025.php:24 的平台判断不命中 Windows 时进入 025.php:28 的 else 分支，在 025.php:30 执行 `$cmd = shell_exec( 'ping  -c 4 ' . $target );`。`target` 未做任何转义、白名单或参数化，直接字符串拼接进入 `shell_exec`，`;`、`|`、`&&`、`$()`、反引号等 shell 元字符可注入任意命令。该分支覆盖 Linux/Unix 等非 Windows 平台，是更常见的部署环境，外部未认证即可触发。

**source / sink**

- source：query `ip`（025.php:5）
- sink：025.php:30 $cmd = shell_exec( 'ping  -c 4 ' . $target );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `025.php:5` | 从 query `ip` 读取外部输入 | 污点进入 target |  |
| 2 | `025.php:30` | 危险汇点：$cmd = shell_exec( 'ping  -c 4 ' . $target ); | 污点进入 command_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /025（ANY）的 OS 命令注入 POC。注入点：ANY 参数 ip；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/025'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 OS 命令注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/025?ip=%3Bid'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/GEN-eff51e7cd060`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

远程未认证攻击者在 *nix 主机上以 Web 服务进程权限执行任意系统命令（RCE），可读取敏感文件、植入后门、提权与横向移动。例如 `ip=127.0.0.1; id` 会执行 `id`。

**CVE / CWE 论证**

CWE-78（OS Command Injection）：查询参数 `ip` 经 `target` 未净化拼接进 `shell_exec`，source→sink 链闭合；端点公开、无需认证，外部可达；利用前提仅为非 Windows 平台（025.php:28 分支），属常规部署环境，不构成额外权限门槛。

**修复建议**

改用参数数组方式执行命令（`proc_open` 传数组参数）或使用不经过 shell 的 ping 实现；对 `ip` 使用 `filter_var($ip, FILTER_VALIDATE_IP)` 严格白名单校验并拒绝非法输入；如必须拼接，使用 `escapeshellarg`/`escapeshellcmd` 并固定命令前缀；以最小权限运行服务。

**验证说明**

静态证据：入口 ANY /025；source=query/ip；sink=025.php:30；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：HTTP 请求 `?ip=<payload>` → 025.php:5 读取 query `ip` 到 `target` → 025.php:24 判断非 Windows，进入 025.php:28 else 分支 → 025.php:30 `shell_exec('ping  -c 4 ' . $target)` 拼接执行 → shell 解释元字符 → 任意命令执行。
PocWriter 建议（未采纳，缺少端点 /025）：针对 025.php 第 30 行 OS 命令注入的 POC。外部输入来自 query 参数 ip，未净化即拼入系统命令执行 sink，可导致任意命令执行（CWE-78）。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /025）：符合 CWE-78（OS 命令注入）。漏洞位于 025.php:30，外部输入来自 query 参数 ip，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。脚本中的 TARGET 需由授权测试人员手动替换；禁止用于未授权目标。

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
| safety_guard | 安全防护 | 2.92 | 是 |
| surface_mapper | 攻击面测绘 | 7.43 | 是 |
| deep_finder | LLM 深挖 | 8.22 | 是 |
| candidate_screener | 候选筛选 | 4.86 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.53 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.83 | 是 |
| coordinator | 管线协调 | 6.14 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
