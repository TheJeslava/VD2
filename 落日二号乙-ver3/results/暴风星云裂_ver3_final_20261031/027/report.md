# 落日二号乙漏洞挖掘报告 — 20261031-014112-90063e

- 生成时间：2026-10-30T17:41:52.023998+00:00
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

本次汇总 3 条已去重 finding，全部集中在单文件 PHP 脚本 027.php，类型均为 command_injection（CWE-78），严重度 critical，且 3 条均带 POC。最高危的是 LLM-c9f36281b7cf：027.php 第 27 行附近通过 $_REQUEST['ip'] 拼接进 shell_exec，黑名单仅过滤 && 与 ;，可用管道符、换行、$() 等绕过，属可直接命令执行的高危缺陷；GEN-2b40f95f1bb0（Windows 分支，第 19 行）与 GEN-c4599ae29817（*nix 分支，第 23 行）是同一入口在两条平台分支上的规则命中，与前者构成同一根因的多点证据。POC 齐全（3/3），但均为静态构造的 HTTP 请求文本，未做动态验证，不能宣称已复现。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 804 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅包含单文件 027.php（30 行），已完整审计。该文件是 DVWA 风格的 ping 命令执行示例：$_REQUEST['ip'] 经不完整黑名单（仅过滤 && 与 ;）后直接拼接进 shell_exec，构成未认证远程命令注入，链在文件内完整闭合，POC 可直接构造。未发现其他独立攻击面（无文件操作、无 SQL、无反序列化、无模板、无 SSRF、无上传）。配置类线索（弱加密/弱随机/Cookie/session）在本文件中不存在。未覆盖范围：无其他文件、无路由/部署配置、无依赖清单，无法评估框架层或第三方组件风险。

未覆盖 / 证据缺口：
- 无 HTTP 端点清单与部署配置，无法确认实际访问路径与 PHP 版本
- 无依赖清单，无法评估第三方组件 CVE
- 未提供被隔离文件，无法判断是否存在被刻意排除的高风险文件

## 3. Findings

### F-1: 027.php ping 功能通过 $_REQUEST['ip'] 拼接 shell_exec 导致命令注入（黑名单仅过滤 && 与 ;）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`027.php:3-27`
- **来源**：`llm_finding`

**描述**

027.php 在收到 POST 参数 Submit 后，直接把 $_REQUEST['ip'] 作为 $target，仅用 str_replace 删除 '&&' 和 ';' 两个子串，随后把 $target 拼进 shell_exec('ping -c 4 ' . $target)（Windows 分支为 'ping ' . $target）。黑名单不覆盖管道符 |、命令替换 $()、反引号 ``、换行符、后台符 &、以及 || 等，攻击者可在 ip 参数中注入任意系统命令，以 Web 服务进程权限执行，导致远程代码执行。

**source / sink**

- source：body `ip`（027.php:5）
- sink：027.php:27 shell_exec( 'ping  -c 4 ' . $target ) / shell_exec( 'ping  ' . $target )

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `027.php:3` | 检查 POST 参数 Submit 是否存在，作为进入处理逻辑的开关 | 请求已到达处理分支 |  |
| 2 | `027.php:5` | 从 $_REQUEST['ip'] 读取攻击者完全可控的字符串到 $target | $target = 攻击者原始输入（未过滤） |  |
| 3 | `027.php:8-14` | 黑名单仅包含 '&&' 与 ';'，str_replace 删除这两个子串 | $target 中 '&&' 与 ';' 被删除，但 \|、$()、反引号、换行、&、\|\| 等仍保留 | 黑名单不完整：管道符 \|、命令替换 $()/``、换行符、单个 & 与 \|\| 均未被过滤，可绕过 |
| 4 | `027.php:17-24` | 根据 php_uname 判断操作系统，将 $target 直接字符串拼接进 shell_exec 的 ping 命令 | $target 作为 shell 命令的一部分被 shell_exec 执行 |  |
| 5 | `027.php:27` | 命令输出回显到页面 <pre> 中，攻击者可直接读取命令执行结果 | 命令 stdout 返回给攻击者 |  |

**POC**

针对 /027.php（POST）的 OS 命令注入 POC。注入点为 POST 参数 ip，该参数被拼接进系统命令执行；payload 为 ;id，目标地址使用 TARGET 占位符。

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

未认证攻击者可在服务器上以 Web 进程权限执行任意系统命令，读取敏感文件、横向移动、植入后门，完全控制主机。

**CVE / CWE 论证**

CWE-78 OS 命令注入。外部可达（HTTP POST 参数 ip），无需认证，source→sink 链在 CODE PACK 内完整闭合（027.php:5 → 027.php:19/23），黑名单可被 | 与 $() 绕过，属典型 CVE 级命令注入。

**修复建议**

不要将用户输入拼接进 shell 命令。使用 escapeshellarg() 对 $target 转义，或改用白名单校验（仅允许合法 IP/主机名正则），并优先使用参数化方式（如 proc_open 传数组参数）执行 ping。

**验证说明**

需动态确认目标操作系统分支（Windows/Linux）与 Web 进程权限；确认 shell_exec 未被 disable_functions 禁用；确认 027.php 的实际部署路径与访问方式。
模型 POC 要点：向 027.php 提交 ip 参数，利用未被过滤的管道符或命令替换执行任意命令，并通过页面回显读取结果
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /027.php）：符合 CWE-78（OS 命令注入）。漏洞位于 027.php:27，外部输入来自 POST body 参数 ip，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标统一使用 TARGET 占位符；如需验证命令执行，优先使用 id/whoami 等只读命令，避免破坏性操作。

### F-2: 027.php Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`027.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入（027.php:5 读取到 `$target`），该值未经任何转义或白名单校验，在 Windows 分支（`stristr(php_uname('s'),'Windows NT')` 为真，027.php:17）被直接字符串拼接到 `shell_exec('ping  ' . $target)`（027.php:19）。由于拼接发生在 shell 解释之前，`$target` 中的 `&`、`|`、`;`（Windows cmd 下 `&`/`|`）等元字符会被 shell 解析为命令分隔符，从而执行攻击者附加的任意命令。代码中未见 escapeshellarg/escapeshellcmd、白名单或参数化调用，校验完全缺失。

**source / sink**

- source：query `ip`（027.php:5）
- sink：027.php:19 $cmd = shell_exec( 'ping  ' . $target );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `027.php:5` | 从 query `ip` 读取外部输入 | 污点进入 target |  |
| 2 | `027.php:19` | 危险汇点：$cmd = shell_exec( 'ping  ' . $target ); | 污点进入 command_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /027（任意方法）的 OS 命令注入 POC。注入点为查询参数 ip，该参数被拼接进系统命令执行；payload 为 ;id，目标地址使用 TARGET 占位符。

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

远程命令执行（RCE）：攻击者可在 Web 服务进程权限下执行任意系统命令，读取/篡改应用与系统文件、窃取数据库凭据、横向移动，完全失陷主机。无需认证即可通过 GET 请求触发。

**CVE / CWE 论证**

CWE-78（OS Command Injection）。外部可达性：入口为公开 HTTP 查询参数 `ip`（027.php:5），无需认证；利用链闭合：`ip` → `$target` → 字符串拼接 → `shell_exec`（027.php:19），中间无净化，shell 元字符可注入。属于典型的不可信输入直接进入命令解释器。

**修复建议**

不要用 shell 拼接执行 ping。改用参数数组形式并禁用 shell，例如 PHP 中用 `proc_open`/`exec` 传数组参数，或直接使用 `filter_var($target, FILTER_VALIDATE_IP)` 严格校验为合法 IP 后再以参数化方式调用；同时对输入做白名单（仅允许 IPv4/IPv6 字面量），拒绝含 shell 元字符的输入，并以最小权限账户运行 Web 服务。

**验证说明**

静态证据：入口 ANY /027；source=query/ip；sink=027.php:19；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：027.php:5 从 query `ip` 读取外部输入存入 `$target`；027.php:17 判断为 Windows 后进入 027.php:19，将 `$target` 直接拼接到 `shell_exec('ping  ' . $target)`；因无 escapeshellarg/白名单，`&`、`|` 等元字符被 cmd 解释，攻击者附加命令被执行，形成完整 RCE 链。
PocWriter 建议（未采纳，缺少端点 /027）：符合 CWE-78（OS 命令注入）。漏洞位于 027.php:19，外部输入来自查询参数 ip，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标统一使用 TARGET 占位符；验证时使用 id/whoami 等只读命令。

### F-3: 027.php *nix 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`027.php:21-23`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入（027.php:5 读取到 `$target`），在非 Windows 分支（027.php:21 的 else）被直接拼接到 `shell_exec('ping  -c 4 ' . $target)`（027.php:23）。`$target` 未经 escapeshellarg/escapeshellcmd 或白名单校验，`;`、`|`、`&`、`$()`、反引号等 shell 元字符会被 /bin/sh 解释，导致执行攻击者附加的任意命令。

**source / sink**

- source：query `ip`（027.php:5）
- sink：027.php:23 $cmd = shell_exec( 'ping  -c 4 ' . $target );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `027.php:5` | 从 query `ip` 读取外部输入 | 污点进入 target |  |
| 2 | `027.php:23` | 危险汇点：$cmd = shell_exec( 'ping  -c 4 ' . $target ); | 污点进入 command_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /027（任意方法）的 OS 命令注入 POC。注入点为查询参数 ip，该参数被拼接进系统命令执行；payload 为 ;id，目标地址使用 TARGET 占位符。

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

远程命令执行（RCE）：在 *nix 主机上以 Web 进程权限执行任意命令，可读取敏感文件、反弹连接、提权前置、篡改数据。无需认证，GET 请求即可触发。

**CVE / CWE 论证**

CWE-78（OS Command Injection）。外部可达性：公开 HTTP 查询参数 `ip`（027.php:5），无需认证；利用链闭合：`ip` → `$target` → 拼接 → `shell_exec`（027.php:23），无净化，shell 元字符可注入。

**修复建议**

改用参数数组方式执行 ping（如 `proc_open` 传数组、禁用 shell），或先用 `filter_var($target, FILTER_VALIDATE_IP)` 严格校验为合法 IP 字面量并做白名单；禁止将外部输入拼接进 shell 命令字符串，Web 服务以最小权限运行。

**验证说明**

静态证据：入口 ANY /027；source=query/ip；sink=027.php:23；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：027.php:5 从 query `ip` 读取外部输入存入 `$target`；027.php:21 进入 *nix 分支，027.php:23 将 `$target` 直接拼接到 `shell_exec('ping  -c 4 ' . $target)`；缺少转义与白名单，`;`、`|`、`$()` 等被 sh 解释，攻击者命令被执行，形成完整 RCE 链。
PocWriter 建议（未采纳，缺少端点 /027）：符合 CWE-78（OS 命令注入）。漏洞位于 027.php:23，外部输入来自查询参数 ip，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标统一使用 TARGET 占位符；验证时使用 id/whoami 等只读命令。

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
| surface_mapper | 攻击面测绘 | 4.87 | 是 |
| deep_finder | LLM 深挖 | 8.32 | 是 |
| candidate_screener | 候选筛选 | 4.19 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.1 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.02 | 是 |
| coordinator | 管线协调 | 5.59 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
