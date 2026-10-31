# 落日二号乙漏洞挖掘报告 — 20261031-014028-a14ca1

- 生成时间：2026-10-30T17:41:10.734554+00:00
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

本次汇总仅涉及单文件 PHP 脚本 025.php（37 行），共 2 条已去重 finding，均为 command_injection（critical）：LLM-229f7d2e8603 指出 $_REQUEST['ip'] 经黑名单过滤后仍可绕过并进入 ping 命令拼接（行至 30），GEN-2da8a6e02c4e 指出 Windows 分支 ping 命令拼接导致 OS 命令注入（行至 26）。两条同源同汇点，属同一缺陷的模型发现与规则发现双证据，最高危即此命令注入，可直接导致任意命令执行。2 条 finding 均带 POC（has_poc=true），POC 齐全，但均为静态源码推导的文本 POC，未做任何动态验证。其余攻击面（XSS 输出、弱哈希/弱加密/弱随机、Cookie 标志、信任边界）在 surface_notes 中被列为待复核项，本次未形成 finding，属未覆盖而非已排除。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 950 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 025.php（37 行，完整展示）。发现一条闭合的命令注入链：$_REQUEST['ip'] → trim → 不完整黑名单 str_replace → shell_exec 拼接执行，可通过换行符/重定向符绕过黑名单实现 RCE。未发现 SQL 注入、文件操作、反序列化、SSRF、XSS（无 echo 用户输入到 HTML 的路径，$html 仅拼接命令输出）等其它可闭合链。配置类弱点（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）在该文件中均无对应代码，不成立。未覆盖范围：无 php.ini/服务器配置、无端点清单、无依赖清单、无部署暴露信息，无法确认 disable_functions、allow_url_include 等运行时设置对可利用性的影响。

未覆盖 / 证据缺口：
- 无 php.ini/Web 服务器配置，无法确认 shell_exec 是否被禁用
- 无部署与网络暴露信息，无法确认公网可达性
- 无端点/路由清单，入口仅从源码推断
- 无依赖清单与版本历史

## 3. Findings

### F-1: 025.php ping 功能通过 $_REQUEST['ip'] 造成命令注入（黑名单可绕过）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`025.php:5-30`
- **来源**：`llm_finding`

**描述**

025.php 在收到 POST 参数 Submit 后，从 $_REQUEST['ip'] 读取攻击者可控输入 $target，仅用 str_replace 做黑名单替换（过滤 ||、&、;、'| '、-、$、(、)、`），随后直接拼接进 shell_exec('ping -c 4 ' . $target)（Windows 分支为 shell_exec('ping  ' . $target)）。黑名单未过滤换行符 \n、空格、重定向符 >、<、以及未被列出的管道写法（如 '|' 后不带空格、'||' 被替换后残留等），且 str_replace 是单次替换，可用双写绕过（如 '||' 被替换为空后仍可构造）。攻击者可通过换行符或空格+重定向/管道注入任意系统命令，实现远程代码执行。

**source / sink**

- source：body `ip`（025.php:5）
- sink：025.php:30 shell_exec('ping -c 4 ' . $target) 与 shell_exec('ping  ' . $target)

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `025.php:3` | 检测到 POST 参数 Submit 存在，进入处理分支 | 请求进入处理逻辑 |  |
| 2 | `025.php:5` | 从 $_REQUEST['ip'] 读取攻击者输入并 trim | $target = 攻击者可控字符串 |  |
| 3 | `025.php:8-21` | 用 str_replace 对黑名单字符做单次替换，未过滤换行符、空格、>、<、未带空格的 \| 等 | $target 仍保留可注入字符（如 \n、>、\|） | 黑名单不完整且为单次替换，换行符与重定向符未列入，可绕过 |
| 4 | `025.php:30` | 将 $target 直接拼接进 shell_exec 执行 ping 命令 | 命令字符串 'ping -c 4 ' . $target 交给 shell 执行 | 无参数化/转义（未用 escapeshellarg），直接字符串拼接 |

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
- POC 目录：`poc/LLM-229f7d2e8603`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

未认证攻击者可在服务器上执行任意系统命令，完全控制 Web 服务器，读取/篡改数据、横向移动。

**CVE / CWE 论证**

CWE-78 OS 命令注入。外部 HTTP 参数 ip 直接进入 shell_exec，黑名单可绕过，无需认证，链路在单文件内闭合。

**修复建议**

不要将用户输入拼接进 shell 命令；使用 escapeshellarg() 对 $target 转义，或使用白名单校验 IP 格式（filter_var($target, FILTER_VALIDATE_IP)），并避免使用 shell_exec。

**验证说明**

需动态确认 shell_exec 未被 disable_functions 禁用、Web 用户权限，以及实际 OS 分支（Linux/Windows）以确定 payload 细节。
模型 POC 要点：利用换行符绕过黑名单，在 ping 命令后追加任意命令执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /025.php）：针对 025.php 的 OS 命令注入 POC（POST 通道）。注入点为 POST 表单参数 ip，其值被拼接进系统命令执行（025.php:30 附近），未做有效净化。payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /025.php）：符合 CWE-78（OS 命令注入）。漏洞位于 025.php:30，外部输入来自 POST body 参数 ip，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭沙箱。执行前将 TARGET 替换为授权目标；payload 中 ;id 可替换为其他只读命令用于验证，禁止使用破坏性命令。

### F-2: 025.php Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`025.php:24-26`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入，该输入在 025.php:5 被读入变量 `target`，随后未经任何转义或白名单校验，在 025.php:24 判断 `php_uname('s')` 含 'Windows NT' 时进入 Windows 分支，于 025.php:26 直接拼接进 `shell_exec('ping  ' . $target)`。由于 `shell_exec` 将整串交给系统 shell 解释，`target` 中的 `&`、`|`、`&&`、`;` 等元字符会被 shell 当作命令分隔符执行，校验完全缺失，污点直达危险汇点。

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

远程未认证攻击者可在 Web 服务器进程权限下执行任意系统命令，导致服务器完全失陷（RCE）、敏感文件读取、内网横向移动与持久化。

**CVE / CWE 论证**

CWE-78（OS 命令注入）。外部可达性：注入点为公开 HTTP 查询参数 `ip`，无需认证；利用链闭合：`ip` → `target`（025.php:5）→ `shell_exec('ping  ' . $target)`（025.php:26），中间无净化、无参数化、无白名单，攻击者可控字符串直接进入 shell 解释器，满足命令注入的全部要素。

**修复建议**

不要用字符串拼接构造 shell 命令。改用参数化执行，例如在 PHP 中用 `escapeshellarg($target)` 包裹参数并配合 `escapeshellcmd`，或使用 `proc_open` 传入参数数组；同时对 `ip` 做严格白名单校验（仅允许 IPv4/IPv6 字面量，如 `filter_var($target, FILTER_VALIDATE_IP)`），校验失败直接拒绝；以最小权限账户运行 Web 服务。

**验证说明**

静态证据：入口 ANY /025；source=query/ip；sink=025.php:26；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `025.php?ip=127.0.0.1%26whoami` → 025.php:5 读取 `ip` 存入 `target` → 025.php:24 命中 Windows 分支 → 025.php:26 拼接为 `ping  127.0.0.1&whoami` 交给 `shell_exec` → shell 执行 `whoami`，命令注入成立。
PocWriter 建议（未采纳，缺少端点 /025）：针对 025.php 的 OS 命令注入 POC（query 通道）。注入点为查询参数 ip，其值被拼接进系统命令执行（025.php:26 附近），未做有效净化。payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /025）：符合 CWE-78（OS 命令注入）。漏洞位于 025.php:26，外部输入来自 query 参数 ip，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭沙箱。执行前将 TARGET 替换为授权目标；payload 中 ;id 可替换为其他只读命令用于验证，禁止使用破坏性命令。

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
| `command_injection` | CWE-78 | 是 | 2 |
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
| safety_guard | 安全防护 | 2.34 | 是 |
| surface_mapper | 攻击面测绘 | 8.17 | 是 |
| deep_finder | LLM 深挖 | 7.81 | 是 |
| candidate_screener | 候选筛选 | 4.27 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.01 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.45 | 是 |
| coordinator | 管线协调 | 5.77 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
