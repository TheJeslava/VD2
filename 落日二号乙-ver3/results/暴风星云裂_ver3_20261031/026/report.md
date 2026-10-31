# 落日二号乙漏洞挖掘报告 — 20261031-010125-909bc8

- 生成时间：2026-10-30T17:02:09.393974+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\026.zip`
- 输入模式：`zip`
- SHA256：`7273281abb4c6a51c2b466c5f7fb770cc8a05c6b22a7a39a27ade9248e1a1d28`
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

本次汇总基于已去重的 3 条 findings，全部集中在单文件 PHP 脚本 026.php，类型均为 command_injection（CWE-78），严重度 critical：LLM-3ff09f0d6739 指出 ping 功能通过 $_REQUEST['ip'] 流入 shell_exec（第 18 行附近），GEN-a86a53dc898b 与 GEN-78a67b34378e 分别对应 Windows 分支（第 10 行）与 *nix 分支（第 14 行）的 OS 命令拼接。最高危项即该命令注入链：外部请求参数未经净化直达命令执行汇点，属最短利用链，可导致任意命令执行。3 条 findings 均标记 has_poc=true，POC 文本齐全，但均为静态源码推断产物，未做动态验证，不能宣称已可动态复现。二次注入链：本次输入未提供任何二次注入链，故不涉及。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 533 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 026.php（21 行），已完整审计。该脚本为 ping 工具示例，$_REQUEST['ip'] 未经任何净化直接拼接进 shell_exec，构成未认证命令注入（RCE），链在源码内完整闭合。surface_notes 中提到的 weak_hash/hardcoded_secret/insecure_cookie/weak_random/trust_boundary 等线索在源码中均无对应实现（无 md5/sha1、无凭据、无 setcookie/session、无 rand、无 X-Forwarded-For 使用），故不单独立项。未提供 php.ini/部署配置，disable_functions 与运行 OS 需动态确认。

未覆盖 / 证据缺口：
- 缺少 php.ini/Web 服务器配置，无法确认 disable_functions、allow_url_include 等开关
- 无端点/路由与认证信息，部署形态（Web/CLI）待确认
- 无依赖清单与版本历史

## 3. Findings

### F-1: 026.php ping 功能通过 $_REQUEST['ip'] 造成命令注入（shell_exec）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`026.php:3-18`
- **来源**：`llm_finding`

**描述**

脚本在收到 POST 参数 Submit 后，直接把 $_REQUEST['ip'] 拼接到 shell_exec('ping -c 4 ' . $target)（Windows 分支为 'ping ' . $target）中执行，未做任何白名单、转义（escapeshellarg/escapeshellcmd）或输入校验。攻击者可通过 ip 参数注入 shell 元字符（; | & $() 反引号 换行等），在服务器上以 Web 进程权限执行任意命令，形成完整 RCE。

**source / sink**

- source：body `ip`（026.php:5）
- sink：026.php:18 shell_exec('ping  -c 4 ' . $target)（026.php:14）与 shell_exec('ping  ' . $target)（026.php:10）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `026.php:3` | 检查 POST 参数 Submit 是否存在，作为进入处理逻辑的开关 | 攻击者控制请求体，Submit 置任意值即可进入 |  |
| 2 | `026.php:5` | 从 $_REQUEST['ip'] 读取外部输入并赋给 $target，无任何过滤 | 原始攻击者字符串，未净化 |  |
| 3 | `026.php:8` | 通过 php_uname('s') 判断操作系统，选择对应分支（不影响注入） | 仅决定拼接前缀，$target 不变 |  |
| 4 | `026.php:14` | 将 $target 直接字符串拼接到 ping 命令并交给 shell_exec 执行（*nix 分支） | 拼接为 'ping  -c 4 ' + payload，交由 /bin/sh -c 解析 | 无 escapeshellarg/escapeshellcmd、无白名单、无字符过滤，shell 元字符原样进入命令 |
| 5 | `026.php:18` | 命令输出回显到页面 <pre> 中，攻击者可直接读取执行结果 | 命令 stdout 写入 $html 并输出 |  |

**POC**

针对 /026.php（POST）的 OS 命令注入 POC。注入点：POST 参数 ip；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/026.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 OS 命令注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/026.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'ip=%3Bid'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/LLM-3ff09f0d6739`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

未认证远程攻击者可在 Web 服务器上以 PHP 进程权限执行任意系统命令，完全控制主机、读取敏感文件、横向移动。

**CVE / CWE 论证**

CWE-78 OS Command Injection。外部 HTTP 参数 ip 经 $_REQUEST 直达 shell_exec，无认证、无过滤，source→sink 链在 CODE PACK 内完整闭合，属典型可申报 CVE 的 RCE。

**修复建议**

不要将用户输入拼入 shell 命令；改用 escapeshellarg($target) 并对 ip 做严格 IP 格式校验（filter_var FILTER_VALIDATE_IP），或使用参数数组方式调用（如 proc_open 传数组）避免 shell 解析。

**验证说明**

需动态确认 shell_exec 未被 disable_functions 禁用、Web 进程权限及操作系统分支；payload 分隔符需按目标 OS 调整（Windows 用 & 或 |）。
模型 POC 要点：向 026.php 提交 ip 参数，利用分号/管道截断 ping 命令并执行任意系统命令，输出回显在页面中
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /026.php）：针对 026.php（POST 入口）的 OS 命令注入 POC。注入点为 POST body 参数 ip，payload 为 ;id，目标地址统一使用 TARGET 占位符。仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /026.php）：符合 CWE-78（OS 命令注入）。漏洞位于 026.php:18，外部输入来自 POST body 参数 ip，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭沙箱。执行前将 TARGET 替换为授权测试实例地址；payload 中 ; 需 URL 编码为 %3B。建议先用无副作用命令（如 id）验证，避免使用破坏性命令。

### F-2: 026.php Windows 分支 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`026.php:8-10`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入（026.php:5 读取该参数并赋给 `$target`）。程序在 026.php:8 用 `stristr(php_uname('s'),'Windows NT')` 判断运行平台，命中 Windows 分支后，在 026.php:10 执行 `$cmd = shell_exec( 'ping  ' . $target );`。`$target` 未经任何转义、白名单校验或参数化处理，被直接拼接到 shell 命令字符串中，因此 `&`、`|`、`&&`、`;` 等 shell 元字符会被解释为命令分隔符，导致任意命令执行。该分支的校验完全缺失，属于典型的字符串拼接式命令注入。

**source / sink**

- source：query `ip`（026.php:5）
- sink：026.php:10 $cmd = shell_exec( 'ping  ' . $target );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `026.php:5` | 从 query `ip` 读取外部输入 | 污点进入 target |  |
| 2 | `026.php:10` | 危险汇点：$cmd = shell_exec( 'ping  ' . $target ); | 污点进入 command_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /026（ANY）的 OS 命令注入 POC。注入点：ANY 参数 ip；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/026'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 OS 命令注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/026?ip=%3Bid'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/GEN-a86a53dc898b`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

远程未认证攻击者可在 Windows 主机上以 Web 服务进程权限执行任意系统命令，导致服务器完全失陷、数据泄露、横向移动与持久化。

**CVE / CWE 论证**

CWE-78（OS 命令注入）。外部可达性：注入点来自 HTTP query 参数 `ip`，无需认证即可触发；利用链闭合：`ip` → `$target`（026.php:5）→ `shell_exec('ping  ' . $target)`（026.php:10），中间无净化函数，攻击者可控拼接内容直接进入 shell 解释器。

**修复建议**

不要用字符串拼接构造 shell 命令。改用参数数组形式并避免 shell 解释，例如在 PHP 中使用 `escapeshellarg($target)` 对参数做严格转义，或使用 `proc_open` 传入参数数组；同时对 `$target` 做严格白名单校验（仅允许合法 IP/域名正则，如 `^[a-zA-Z0-9.\-]+$`），并遵循最小权限运行 Web 服务。

**验证说明**

静态证据：入口 ANY /026；source=query/ip；sink=026.php:10；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `026.php?ip=TARGET` 形式，将 `ip` 参数值设为包含 shell 元字符的载荷（如 `127.0.0.1 & whoami`）。026.php:5 读取该参数到 `$target`；026.php:8 在 Windows 平台判定为真；026.php:10 将 `$target` 原样拼入 `ping  ` 命令并交给 `shell_exec`，元字符被 shell 解释，附加命令以 Web 进程权限执行。
PocWriter 建议（未采纳，缺少端点 /026）：针对 026（ANY 方法入口）的 OS 命令注入 POC。注入点为 query 参数 ip，payload 为 ;id，目标地址统一使用 TARGET 占位符。仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /026）：符合 CWE-78（OS 命令注入）。漏洞位于 026.php:10，外部输入来自 query 参数 ip，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭沙箱。执行前将 TARGET 替换为授权测试实例地址；payload 中 ; 需 URL 编码为 %3B。ANY 表示任意方法均可，实际测试建议用 GET 或 POST 各试一次以确认参数解析路径。

### F-3: 026.php *nix 分支 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`026.php:12-14`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入（026.php:5 读取该参数并赋给 `$target`）。当 026.php:8 的平台判断不成立时进入 026.php:12 的 else 分支（*nix），在 026.php:14 执行 `$cmd = shell_exec( 'ping  -c 4 ' . $target );`。`$target` 未做任何转义、白名单或参数化处理即被拼接到 shell 命令，`;`、`|`、`&&`、`$()`、反引号等元字符会被 shell 解释，构成任意命令执行。

**source / sink**

- source：query `ip`（026.php:5）
- sink：026.php:14 $cmd = shell_exec( 'ping  -c 4 ' . $target );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `026.php:5` | 从 query `ip` 读取外部输入 | 污点进入 target |  |
| 2 | `026.php:14` | 危险汇点：$cmd = shell_exec( 'ping  -c 4 ' . $target ); | 污点进入 command_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /026（ANY）的 OS 命令注入 POC。注入点：ANY 参数 ip；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/026'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 OS 命令注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/026?ip=%3Bid'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/GEN-78a67b34378e`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

远程未认证攻击者可在 Linux/Unix 主机上以 Web 服务进程权限执行任意系统命令，导致服务器失陷、敏感数据泄露、权限提升与横向渗透。

**CVE / CWE 论证**

CWE-78（OS 命令注入）。外部可达性：注入点来自 HTTP query 参数 `ip`，无需认证；利用链闭合：`ip` → `$target`（026.php:5）→ `shell_exec('ping  -c 4 ' . $target)`（026.php:14），无净化环节，外部输入直达 shell 解释器。

**修复建议**

避免字符串拼接命令。使用 `escapeshellarg($target)` 转义参数或改用 `proc_open` 参数数组形式；对 `$target` 实施严格白名单（仅允许合法 IP/域名格式），拒绝包含 shell 元字符的输入；以最小权限账户运行 Web 服务。

**验证说明**

静态证据：入口 ANY /026；source=query/ip；sink=026.php:14；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `026.php?ip=TARGET`，将 `ip` 设为如 `127.0.0.1; id` 的载荷。026.php:5 读取到 `$target`；026.php:8 平台判断为假进入 else 分支；026.php:14 将 `$target` 原样拼入 `ping  -c 4 ` 并交给 `shell_exec`，`;` 后的命令被 shell 执行，实现任意命令执行。
PocWriter 建议（未采纳，缺少端点 /026）：针对 026（ANY 方法入口）的 OS 命令注入 POC。注入点为 query 参数 ip，payload 为 ;id，目标地址统一使用 TARGET 占位符。仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /026）：符合 CWE-78（OS 命令注入）。漏洞位于 026.php:14，外部输入来自 query 参数 ip，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭沙箱。执行前将 TARGET 替换为授权测试实例地址；payload 中 ; 需 URL 编码为 %3B。与 GEN-a86a53dc898b 为同一文件不同行（14 行）的 sink，测试时注意区分触发分支。

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
| safety_guard | 安全防护 | 2.71 | 是 |
| surface_mapper | 攻击面测绘 | 7.19 | 是 |
| deep_finder | LLM 深挖 | 7.81 | 是 |
| candidate_screener | 候选筛选 | 4.18 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.04 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.34 | 是 |
| coordinator | 管线协调 | 6.73 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
