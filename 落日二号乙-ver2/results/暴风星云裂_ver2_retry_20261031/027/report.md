# 落日二号乙漏洞挖掘报告 — 20261031-002105-cd2c02

- 生成时间：2026-10-30T16:21:49.738401+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\027.zip`
- 输入模式：`zip`
- SHA256：`0692e8f3bcf09553285200fdbb5eecd31f5db885c7d44a68982905afded500d3`
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

本次审计范围仅限单文件 PHP 脚本 027.php（约 30 行），共交付 3 条 command_injection 发现，全部为 critical 且均带 POC：LLM-c9f36281b7cf（ip 参数经 shell_exec 黑名单可绕过，第 27 行）、GEN-2b40f95f1bb0（Windows 分支 ping 命令拼接，第 19 行）、GEN-c4599ae29817（*nix 分支 ping -c 4 命令拼接，第 23 行）。最高危为 027.php 中 ip 参数到 shell_exec 的直接污点链，黑名单过滤可绕过，属可远程触发的 OS 命令注入（CWE-78）。POC 齐全（3/3），但均为静态源码推断的文本 POC，未做动态验证；且缺少 php.ini/disable_functions 信息，无法确认 exec/shell_exec 在目标环境是否可用。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 804 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 027.php（30 行，全量逐行审计）。确认一条闭合的命令注入链：$_REQUEST['ip']（027.php:5）经仅过滤 '&&'/';' 的 str_replace 黑名单（027.php:8-14）后直接拼接进 shell_exec（027.php:19/23），输出回显于 027.php:27，构成未授权 RCE。medium_review_items 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 在该文件中均无对应实现（无 md5/sha1、无自造加密、无 rand 令牌、无 setcookie、无信任 X-Forwarded-* 等），故不单独立项。未发现 prompt_injection 诱导文本。code_pack 之外无其它文件，依赖版本、php.ini、部署与认证上下文均无法确认，属未覆盖范围。

未覆盖 / 证据缺口：
- 无 composer.json/框架配置，无法评估依赖 CVE
- 无端点清单，无法确认是否位于认证/WAF 之后
- 缺少 php.ini（disable_functions、open_basedir），无法确认 shell_exec 可用性
- 无部署与运行环境信息，无法确认外网暴露面

## 3. Findings

### F-1: 027.php ping 功能通过 ip 参数导致命令注入（shell_exec 黑名单可绕过）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`027.php:3-27`
- **来源**：`llm_finding`

**描述**

027.php 在收到 POST 参数 Submit 后，从 $_REQUEST['ip'] 读取用户输入，仅用 str_replace 删除 '&&' 与 ';' 两个字符串作为黑名单，随后直接拼接进 shell_exec('ping -c 4 ' . $target)（Windows 分支为 shell_exec('ping  ' . $target)）。黑名单只过滤 '&&' 和 ';'，未过滤管道符 '|'、命令替换 '$(...)'、反引号、换行、'||'、'&' 等 shell 元字符，也未使用 escapeshellarg/escapeshellcmd，因此攻击者可注入任意系统命令并以 Web 进程权限执行，形成 RCE。

**source / sink**

- source：body `ip`（027.php:5）
- sink：027.php:27 shell_exec('ping  -c 4 ' . $target) / shell_exec('ping  ' . $target)

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `027.php:3` | 检测到 POST 参数 Submit，进入命令执行分支 | 请求进入处理逻辑 |  |
| 2 | `027.php:5` | 从 $_REQUEST['ip'] 读取攻击者可控输入赋给 $target | 原始用户字符串，未净化 |  |
| 3 | `027.php:8-14` | 仅用 str_replace 删除 '&&' 与 ';' 两个子串 | 过滤后字符串，仍保留 \|、$()、反引号、换行、\|\|、& 等 shell 元字符 | 黑名单只覆盖 '&&' 和 ';'，可用管道符 '\|'、命令替换 '$(...)'、反引号或 '\|\|' 绕过；且未使用 escapeshellarg |
| 4 | `027.php:19` | Windows 分支将 $target 直接拼接进 shell_exec('ping  ' . $target) | 拼接进 shell 命令字符串 |  |
| 5 | `027.php:23` | *nix 分支将 $target 直接拼接进 shell_exec('ping  -c 4 ' . $target) | 拼接进 shell 命令字符串，交由 /bin/sh 解析执行 |  |
| 6 | `027.php:27` | 命令输出回显到页面 <pre> 中，攻击者可直接读取命令执行结果 | 命令 stdout 回显 |  |

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

远程未授权攻击者可在 Web 服务器上以 Web 进程权限执行任意系统命令，读取敏感文件、横向移动、植入后门，完全控制主机。

**CVE / CWE 论证**

CWE-78 OS 命令注入。外部 HTTP 可达，无需认证，source（$_REQUEST['ip']）到 sink（shell_exec）链路在 027.php 内完整闭合，黑名单可被常见 shell 元字符绕过，属典型可申报 CVE 的 RCE。

**修复建议**

不要将用户输入拼接进 shell 命令；改用 escapeshellarg($target) 对参数整体转义，或使用白名单校验 IP 格式（filter_var($target, FILTER_VALIDATE_IP)），并避免使用 shell_exec 执行外部命令。

**验证说明**

需在目标环境确认 shell_exec 未被 disable_functions 禁用、Web 进程权限，以及实际 shell 解析行为（/bin/sh 对 | 与 $() 的处理）；POC 仅限授权测试。
模型 POC 要点：向 027.php 提交 ip 参数，利用管道符或命令替换绕过 '&&'/';' 黑名单，在 ping 命令后追加任意命令并回显结果。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /027.php）：针对 027.php 第 27 行 OS 命令注入的 POC。注入点为 POST 请求体参数 ip，payload 为 ;id，目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /027.php）：符合 CWE-78（OS 命令注入）。漏洞位于 027.php:27，外部输入来自 POST body 参数 ip，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网；目标统一使用 TARGET 占位符。执行前请替换 TARGET 为授权实例地址。

### F-2: 027.php Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`027.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP query 参数 `ip` 提供输入，027.php:5 将其读入 `$target`；027.php:17 用 `stristr(php_uname('s'),'Windows NT')` 判断运行平台，命中 Windows 分支后，027.php:19 执行 `$cmd = shell_exec( 'ping  ' . $target );`，把外部输入直接字符串拼接进 shell 命令。代码中未见 escapeshellarg/escapeshellcmd、白名单校验或 IP 格式规范化，因此 `$target` 中的 `&`、`|`、`;`、`&&` 等 shell 元字符会被解释为命令分隔符，校验完全失效，污点直达 shell_exec 汇点。

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

远程未认证攻击者可在 Web 服务器进程权限下执行任意系统命令（Windows 分支），导致服务器被完全控制、读取/篡改任意文件、横向移动；属于 RCE 级影响。

**CVE / CWE 论证**

CWE-78（OS Command Injection）。外部可达性：入口为 HTTP query 参数 `ip`（027.php:5），无需认证；利用链闭合：`ip` → `$target` → 字符串拼接 → `shell_exec`（027.php:19），中间无有效净化，攻击者可控命令分隔符即可追加任意命令。

**修复建议**

不要用 shell 拼接执行 ping：改用参数数组形式（如 proc_open/exec 传数组）或直接使用语言内置的 ICMP/网络库；若必须调用外部程序，对 `$target` 做严格白名单校验（仅允许合法 IPv4/IPv6 字符集与格式，用 filter_var FILTER_VALIDATE_IP），并配合 escapeshellarg 作为纵深防御；以最小权限账户运行 Web 服务。

**验证说明**

静态证据：入口 ANY /027；source=query/ip；sink=027.php:19；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `027.php?ip=TARGET;任意命令` → 027.php:5 读取 `ip` 到 `$target` → 027.php:17 平台判断进入 Windows 分支 → 027.php:19 `shell_exec('ping  ' . $target)` 拼接执行 → shell 解析注入的命令分隔符并执行攻击者命令。
PocWriter 建议（未采纳，缺少端点 /027）：针对 027.php 第 19 行 OS 命令注入的 POC。注入点为请求参数 ip（query 通道），payload 为 ;id，目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /027）：符合 CWE-78（OS 命令注入）。漏洞位于 027.php:19，外部输入来自 query 参数 ip，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网；目标统一使用 TARGET 占位符。执行前请替换 TARGET 为授权实例地址。

### F-3: 027.php *nix 分支 ping -c 4 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`027.php:21-23`
- **来源**：`rule`

**描述**

攻击者通过 HTTP query 参数 `ip` 提供输入，027.php:5 将其读入 `$target`；当 027.php:17 的平台判断不命中 Windows 时进入 else 分支，027.php:23 执行 `$cmd = shell_exec( 'ping  -c 4 ' . $target );`，外部输入被直接拼接进 shell 命令。代码中未见 escapeshellarg/escapeshellcmd、白名单或 IP 格式校验，`;`、`|`、`&&`、`$()`、反引号等 shell 元字符可突破 ping 参数边界执行任意命令，校验无效，污点直达 shell_exec 汇点。

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

远程未认证攻击者在 *nix 部署下可以 Web 服务进程权限执行任意系统命令，实现 RCE、读取敏感文件、建立持久化或横向渗透。

**CVE / CWE 论证**

CWE-78（OS Command Injection）。外部可达性：HTTP query 参数 `ip`（027.php:5）无需认证即可控制；利用链闭合：`ip` → `$target` → 拼接 → `shell_exec`（027.php:23），无有效净化，命令分隔符可控。

**修复建议**

避免 shell 字符串拼接，改用参数数组方式调用外部程序或使用内置网络库；对 `$target` 使用 filter_var(..., FILTER_VALIDATE_IP) 严格校验并拒绝非法字符，必要时叠加 escapeshellarg；以最小权限运行服务并限制出站能力。

**验证说明**

静态证据：入口 ANY /027；source=query/ip；sink=027.php:23；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `027.php?ip=TARGET;任意命令` → 027.php:5 读取 `ip` 到 `$target` → 027.php:17 判断为非 Windows 进入 else → 027.php:23 `shell_exec('ping  -c 4 ' . $target)` 拼接执行 → shell 解释注入的元字符执行攻击者命令。
PocWriter 建议（未采纳，缺少端点 /027）：针对 027.php 第 23 行 OS 命令注入的 POC。注入点为请求参数 ip（query 通道），payload 为 ;id，目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /027）：符合 CWE-78（OS 命令注入）。漏洞位于 027.php:23，外部输入来自 query 参数 ip，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网；目标统一使用 TARGET 占位符。执行前请替换 TARGET 为授权实例地址。

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
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.58 | 是 |
| surface_mapper | 攻击面测绘 | 7.39 | 是 |
| deep_finder | LLM 深挖 | 9.05 | 是 |
| candidate_screener | 候选筛选 | 4.59 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.82 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.91 | 是 |
| coordinator | 管线协调 | 5.35 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
