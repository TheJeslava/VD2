# 落日二号乙漏洞挖掘报告 — 20261031-214507-a702fd

- 生成时间：2026-10-31T13:46:01.925241+00:00
- 输入：`$WORKSPACE\暴风星云裂\026.zip`
- 输入模式：`zip`
- SHA256：`7273281abb4c6a51c2b466c5f7fb770cc8a05c6b22a7a39a27ade9248e1a1d28`
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

本次汇总基于已去重的 3 条 findings，全部集中在单文件 PHP 脚本 026.php，类型均为 command_injection（CWE-78），严重度 critical：LLM-3ff09f0d6739 指出通过 $_REQUEST['ip'] 拼接进 shell_exec 形成 RCE（第 18 行附近），GEN-a86a53dc898b 与 GEN-78a67b34378e 分别对应 Windows 分支（第 10 行附近）与 *nix 分支（第 14 行附近）的 ping 命令拼接。三者本质是同一处“请求参数直连命令汇点”的不同分支/不同检出器表述，最高危即该命令注入链，可直接导致远程命令执行。3 条均带 POC（has_poc=true），但均为静态源码推断型 POC，未做动态验证，不能宣称已可动态复现。二次注入链：本次输入未提供，无。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 533 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 026.php（21 行），已逐行审计。确认一条闭合的命令注入链：$_REQUEST['ip']（第 5 行）未经任何过滤直接拼接到 shell_exec（第 10/14 行），Submit 参数控制进入分支（第 3 行），命令输出经 $cmd 回显（第 18 行）。未发现 SQL、文件包含、反序列化、SSRF、弱哈希/弱随机/不安全 Cookie 等其他汇点；文件内无认证、会话、配置逻辑。surface_notes 中提到的 weak_hash/weak_random/insecure_cookie/weak_crypto/trust_boundary 在本文件中均无对应代码，不成立。未覆盖范围：无 php.ini、Web 服务器配置、依赖清单，无法确认 disable_functions 与真实部署路径；端点表为空，URL 与 HTTP 方法为按脚本行为推断。输入中未出现诱导性文本，无 prompt_injection 证据。

未覆盖 / 证据缺口：
- 缺少 php.ini/Web 服务器配置，无法确认 shell_exec 是否被禁用及可访问路径
- 无端点清单，URL 与请求方法为推断
- 无依赖清单与其它文件，无法评估更大攻击面

## 3. Findings

### F-1: 026.php ping 功能通过 $_REQUEST['ip'] 拼接 shell_exec 导致命令注入（RCE）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.93`
- **结论**：`candidate` / 证据等级 `externally_corroborated`
- **位置**：`026.php:3-18`
- **来源**：`llm_finding`

**描述**

026.php 在收到 POST 参数 Submit 后，直接把 $_REQUEST['ip'] 拼进 shell_exec('ping -c 4 ' . $target)（Windows 分支为 'ping ' . $target）。$target 未做任何白名单、转义（escapeshellarg/escapeshellcmd）或类型校验，攻击者用 ; | & ` $() 等 shell 元字符即可在服务器上执行任意命令。由于 $_REQUEST 同时接受 GET/POST/Cookie，攻击面更宽。

**source / sink**

- source：body `ip`（026.php:5）
- sink：026.php:18 shell_exec('ping  -c 4 ' . $target)（第 14 行，*nix）/ shell_exec('ping  ' . $target)（第 10 行，Windows）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `026.php:3` | 检查 POST 参数 Submit 是否存在，作为进入处理逻辑的开关 | 攻击者控制请求体，Submit 置任意值即可进入分支 |  |
| 2 | `026.php:5` | 从 $_REQUEST['ip'] 读取攻击者输入并赋给 $target，无任何过滤 | 原始字符串，未过滤、未转义 |  |
| 3 | `026.php:8` | 通过 php_uname('s') 判断操作系统，选择对应命令模板 | 仅决定拼接前缀，不影响污点 |  |
| 4 | `026.php:14` | 将 $target 直接字符串拼接到 'ping -c 4 ' 后传入 shell_exec 执行（Windows 分支为第 10 行） | 污点进入 shell 命令行，元字符被 /bin/sh 解释 | 无 escapeshellarg/escapeshellcmd、无 IP 格式白名单、无字符黑名单 |

**POC**

针对 /026.php（POST）的 OS 命令注入 POC。注入点：POST 参数 Submit；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/026.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 OS 命令注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/026.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'Submit=%3Bid&Submit=Submit'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/LLM-3ff09f0d6739`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

未认证远程攻击者可在 Web 服务器进程权限下执行任意系统命令，完全控制主机，读取敏感文件、横向移动。

**CVE / CWE 论证**

CWE-78 OS 命令注入。source（$_REQUEST['ip']）到 sink（shell_exec 字符串拼接）链路完整、无过滤，外部无需认证即可触发，属典型 CVE 级 RCE。

**修复建议**

不要将用户输入拼入 shell 命令；使用 escapeshellarg($target) 并对 ip 做严格 IP 格式校验（filter_var FILTER_VALIDATE_IP），或改用不经过 shell 的 API。

**验证说明**

需动态确认 shell_exec 未被 disable_functions 禁用、目标 OS 分支（决定 payload 前缀），以及 026.php 的实际可访问 URL。
模型 POC 要点：向 026.php 提交 Submit 与含 shell 元字符的 ip 参数，使 ping 命令后追加任意命令，命令输出经 $cmd 回显在 <pre> 中
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
AWVS 外部佐证：OS Command Injection @ http://127.0.0.1:18081/026.php（未在本管线执行扫描）。
PocWriter 建议（未采纳，缺少端点 /026.php）：针对 026.php（POST）的 OS 命令注入 POC。注入点为 POST 参数 Submit（源码 026.php:18 将该参数拼入系统命令），payload 为 ;id，目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /026.php）：符合 CWE-78（OS 命令注入）。漏洞位于 026.php:18，外部输入来自 POST 参数 Submit，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅限授权测试；脚本为文本工件，不自动执行。执行前将 TARGET 替换为授权目标，并确认 Submit 参数名与源码一致。

**外部佐证**

- awvs: OS Command Injection @ http://127.0.0.1:18081/026.php

### F-2: 026.php Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`026.php:8-10`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入，该参数在 026.php:5 被读入变量 `$target`。026.php:8 使用 `stristr(php_uname('s'), 'Windows NT')` 判断运行平台，命中 Windows 分支后，026.php:10 执行 `$cmd = shell_exec( 'ping  ' . $target );`，将 `$target` 未经任何转义、白名单校验或参数化直接拼接到 shell 命令字符串中。由于 `shell_exec` 会把整串交给系统 shell 解释，`$target` 中的 `&`、`|`、`&&`、`;` 等元字符会被 shell 当作命令分隔符执行，代码中不存在 escapeshellarg/escapeshellcmd 或输入格式校验，因此校验无效。最终危险操作是 026.php:10 的 `shell_exec` 命令执行。

**source / sink**

- source：query `ip`（026.php:5）
- sink：026.php:10 $cmd = shell_exec( 'ping  ' . $target );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `026.php:5` | 从 query `ip` 读取外部输入 | 污点进入 target |  |
| 2 | `026.php:10` | 危险汇点：$cmd = shell_exec( 'ping  ' . $target ); | 污点进入 command_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /026（POST）的 OS 命令注入 POC。注入点：POST 参数 ip；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/026'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 OS 命令注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/026' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'ip=%3Bid&Submit=Submit'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/GEN-a86a53dc898b`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

远程未认证攻击者可在目标 Windows 主机上以 Web 服务进程权限执行任意系统命令，导致服务器完全失陷、敏感数据泄露、横向移动与持久化。属于 RCE 级别影响。

**CVE / CWE 论证**

CWE-78（OS 命令注入）。外部可达性：注入点为 HTTP query 参数 `ip`，无需认证即可访问该脚本；利用链闭合：`ip` → `$target`（026.php:5）→ 字符串拼接（026.php:10）→ `shell_exec` 执行，中间无净化函数。该分支仅在 Windows 平台触发，属平台相关但完全可由攻击者控制输入。

**修复建议**

不要用字符串拼接构造 shell 命令。改用参数数组形式（如 `proc_open`/`exec` 传数组）或对 `$target` 做严格白名单校验（仅允许 IPv4/IPv6 字面量，用 `filter_var($target, FILTER_VALIDATE_IP)` 验证），并在必须拼接时使用 `escapeshellarg($target)`；同时以最小权限账户运行 Web 服务。

**验证说明**

静态证据：入口 POST /026；source=query/ip；sink=026.php:10；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `026.php?ip=<payload>`，026.php:5 将参数写入 `$target`；026.php:8 在 Windows 环境判定为真，进入 026.php:10，`'ping  ' . $target` 被 `shell_exec` 交给 cmd.exe 解释，payload 中的命令分隔符使附加命令被执行，形成完整命令注入链。
PocWriter 建议（未采纳，缺少端点 /026）：针对 026.php（POST）的 OS 命令注入 POC。注入点为 POST 参数 ip（源码 026.php:10 将该参数拼入系统命令），payload 为 ;id，目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /026）：符合 CWE-78。漏洞位于 026.php:10，外部输入来自 POST 参数 ip，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅限授权测试；脚本为文本工件，不自动执行。执行前将 TARGET 替换为授权目标。

### F-3: 026.php *nix 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`026.php:12-14`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入，026.php:5 将其读入 `$target`。当 026.php:8 的平台判断不成立（非 Windows，即 *nix 分支）时，026.php:14 执行 `$cmd = shell_exec( 'ping  -c 4 ' . $target );`，`$target` 未经转义或白名单校验直接拼入 shell 命令。`shell_exec` 将整串交由 `/bin/sh` 解释，`;`、`|`、`&&`、`$()`、反引号等元字符可注入并执行任意命令；代码中无 escapeshellarg/escapeshellcmd 或格式校验，故校验无效。最终危险操作为 026.php:14 的 `shell_exec`。

**source / sink**

- source：query `ip`（026.php:5）
- sink：026.php:14 $cmd = shell_exec( 'ping  -c 4 ' . $target );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `026.php:5` | 从 query `ip` 读取外部输入 | 污点进入 target |  |
| 2 | `026.php:14` | 危险汇点：$cmd = shell_exec( 'ping  -c 4 ' . $target ); | 污点进入 command_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /026（POST）的 OS 命令注入 POC。注入点：POST 参数 ip；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/026'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 OS 命令注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/026' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'ip=%3Bid&Submit=Submit'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/GEN-78a67b34378e`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

远程未认证攻击者可在目标 Linux/Unix 主机上以 Web 服务进程权限执行任意命令，实现 RCE、读取敏感文件、反弹连接与进一步提权，导致服务器失陷。

**CVE / CWE 论证**

CWE-78（OS 命令注入）。外部可达性：注入点为 HTTP query 参数 `ip`，无需认证；利用链闭合：`ip` → `$target`（026.php:5）→ 拼接（026.php:14）→ `shell_exec` 执行，无净化环节。该分支在 *nix 平台触发，是常见部署环境，实际可利用性高。

**修复建议**

使用参数数组方式调用外部程序（`proc_open`/`exec` 传数组参数），或对 `$target` 使用 `filter_var($target, FILTER_VALIDATE_IP)` 严格校验为 IP 字面量；若必须拼接则使用 `escapeshellarg($target)`。同时限制 Web 进程权限并禁用不必要的 shell 函数。

**验证说明**

静态证据：入口 POST /026；source=query/ip；sink=026.php:14；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `026.php?ip=127.0.0.1;id`，026.php:5 写入 `$target`；026.php:8 平台判断为假进入 *nix 分支，026.php:14 将 `'ping  -c 4 ' . $target` 交给 `shell_exec`，shell 解析 `;` 后执行 `id`，完成命令注入。
PocWriter 建议（未采纳，缺少端点 /026）：针对 026.php（POST）的 OS 命令注入 POC。注入点为 POST 参数 ip（源码 026.php:14 将该参数拼入系统命令），payload 为 ;id，目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /026）：符合 CWE-78。漏洞位于 026.php:14，外部输入来自 POST 参数 ip，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅限授权测试；脚本为文本工件，不自动执行。执行前将 TARGET 替换为授权目标。

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
| `LLM-3ff09f0d6739` | OS Command Injection | http://127.0.0.1:18081/026.php | corroborated |

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
| safety_guard | 安全防护 | 5.43 | 是 |
| surface_mapper | 攻击面测绘 | 8.71 | 是 |
| deep_finder | LLM 深挖 | 9.54 | 是 |
| candidate_screener | 候选筛选 | 5.07 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.99 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 9.2 | 是 |
| coordinator | 管线协调 | 7.93 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
