# 落日二号乙漏洞挖掘报告 — 20261031-011827-5328ba

- 生成时间：2026-10-30T17:19:12.204265+00:00
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

本次汇总仅覆盖单文件 PHP 脚本 026.php（21 行），共交付 3 条 command_injection 发现（1 条 llm_finding + 2 条 rule），严重度均为 critical，且 3 条均带 POC。最高危项是 026.php 中通过 $_REQUEST['ip'] 直接拼接进 ping 命令并交由 shell_exec 执行（LLM-3ff09f0d6739，行 18），规则侧另给出 Windows 分支（行 10）与 *nix 分支（行 14）的同类拼接证据，三者实为同一处「读取即使用」的注入点在不同分支上的表现，去重后应视为一个根因。POC 齐全但均为静态构造的 HTTP 请求文本（TARGET 占位），未做任何动态验证，不能宣称已复现。除此之外，weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary 等配置型攻击面在 surface_notes 中被列为待核查项，但没有任何 findings 覆盖，属于未交付而非不存在。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 533 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 026.php（21 行）。已审计全部代码：入口为 POST Submit 触发，污点源为 $_REQUEST['ip']（026.php:5），经字符串拼接直达 shell_exec（026.php:10 与 026.php:14），结果经 $cmd 回显（026.php:18），构成完整未认证命令注入链，已作为 critical 报告。文件中未发现 md5/sha1/rand/setcookie/session 等配置型线索，也无 SQL/文件/反序列化/SSRF 汇点。未覆盖范围：无 php.ini、Web 服务器配置、部署方式与端点清单，无法确认实际 URL 路径与访问控制；但这些不影响命令注入链的成立。

未覆盖 / 证据缺口：
- 无 Web 服务器/php.ini 配置，无法确认 allow_url_include、open_basedir、display_errors 等基线
- 无端点清单，实际 URL 路径与 HTTP 方法需人工确认
- 无部署方式说明，无法确认是否可远程触发及运行用户权限

## 3. Findings

### F-1: 026.php ping 功能通过 $_REQUEST['ip'] 造成命令注入（shell_exec）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`026.php:3-18`
- **来源**：`llm_finding`

**描述**

026.php 在收到 POST 参数 Submit 后，直接把 $_REQUEST['ip'] 拼接到 shell_exec('ping -c 4 ' . $target)（*nix）或 shell_exec('ping ' . $target)（Windows）中执行，未做任何白名单、转义（escapeshellarg/escapeshellcmd）或类型校验。攻击者可通过 ip 参数注入 shell 元字符（;、|、&&、$()、反引号）在服务器上执行任意命令，且命令输出通过 $cmd 回显到页面 <pre> 中，形成可回显的 RCE。由于使用 $_REQUEST，GET/POST/Cookie 均可投递。

**source / sink**

- source：body `ip`（026.php:5）
- sink：026.php:18 shell_exec('ping  -c 4 ' . $target) / shell_exec('ping  ' . $target)

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `026.php:3` | 检查 POST 参数 Submit 是否存在，作为进入处理逻辑的开关 | 请求到达，Submit 存在则进入分支 |  |
| 2 | `026.php:5` | 从 $_REQUEST 读取 ip 参数赋给 $target，无任何过滤 | $target = 攻击者完全可控字符串 |  |
| 3 | `026.php:8` | 通过 php_uname('s') 判断操作系统，选择对应命令模板 | $target 保持不变 |  |
| 4 | `026.php:10` | Windows 分支：字符串拼接后传入 shell_exec | 'ping  ' . $target 直接进入 shell |  |
| 5 | `026.php:14` | *nix 分支：字符串拼接后传入 shell_exec | 'ping  -c 4 ' . $target 直接进入 shell |  |
| 6 | `026.php:18` | 命令执行结果 $cmd 拼入 HTML 回显给用户 | 命令 stdout 回显到页面 |  |

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

未认证远程攻击者可在 Web 服务器进程权限下执行任意系统命令，完全控制主机，读取/篡改数据、横向移动。

**CVE / CWE 论证**

CWE-78 OS 命令注入。外部可达（HTTP 参数 ip），无需认证，source→sink 链在 026.php:5→10/14 完整闭合，命令输出可回显，属典型 CVE 级 RCE。

**修复建议**

不要将用户输入拼入 shell 命令；使用 escapeshellarg($target) 包裹参数，或改用白名单校验 IP 格式（filter_var($target, FILTER_VALIDATE_IP)），并避免使用 shell_exec 拼接。

**验证说明**

需确认 026.php 实际部署可远程访问及 Web 服务器用户权限；命令注入链本身在源码层面已完整闭合。
模型 POC 要点：向 026.php 提交 Submit 与含 shell 元字符的 ip 参数，使 ping 命令后追加任意命令，输出回显在 <pre> 中。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /026.php）：针对 026.php（POST 入口）的 OS 命令注入 POC。注入点为 POST 表单参数 ip，该参数被拼接进系统命令执行（CWE-78）。payload 使用 TARGET 占位符，仅作文本工件。
PocWriter 建议（未采纳，缺少端点 /026.php）：符合 CWE-78（OS Command Injection）。漏洞位于 026.php:18，外部输入来自 POST body 参数 ip，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅限授权测试。目标地址统一使用 TARGET 占位符，需手动替换后由测试人员自行执行；管线不执行、不联网。若 ; 被过滤，可尝试 |、&&、$() 等分隔符变体，但需保持注入通道为 POST 参数 ip。

### F-2: 026.php Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`026.php:8-10`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入（026.php:5 读取该参数并赋给 `$target`）。程序在 026.php:8 用 `stristr(php_uname('s'), 'Windows NT')` 判断运行平台，命中 Windows 分支后，在 026.php:10 直接把 `$target` 拼接到字符串 `'ping  '` 之后交给 `shell_exec()` 执行。代码片段显示拼接前没有任何转义、白名单或参数化处理（无 `escapeshellarg`/`escapeshellcmd`，也无 IP 格式校验），因此 `$target` 中的 shell 元字符（如 `&`、`|`、`;`）会被命令解释器当作命令分隔符执行。

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

远程未认证攻击者可在 Web 服务器进程权限下执行任意系统命令，导致服务器被完全控制、数据泄露、横向移动与持久化；属于 RCE 级影响。

**CVE / CWE 论证**

CWE-78（OS 命令注入）。外部可达性：注入点来自 HTTP query 参数 `ip`，无需认证即可触达 026.php:10 的 `shell_exec`；利用链闭合：`ip` → `$target` → 字符串拼接 → `shell_exec`，中间无有效净化。该分支仅在 Windows 主机上生效（026.php:8 平台判断），非 Windows 环境走 026.php:14 的另一条同类汇点。

**修复建议**

不要用字符串拼接构造 shell 命令。优先使用参数数组形式（如 `proc_open`/`exec` 的数组参数）避免经过 shell；若必须拼接，对 `$target` 使用 `escapeshellarg()` 并配合严格白名单校验（如 `filter_var($target, FILTER_VALIDATE_IP)`），同时以最小权限账户运行 Web 服务。

**验证说明**

静态证据：入口 ANY /026；source=query/ip；sink=026.php:10；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `026.php?ip=<payload>` → 026.php:5 将参数值写入 `$target` → 026.php:8 判定为 Windows 平台 → 026.php:10 执行 `shell_exec('ping  ' . $target)`，payload 中的命令分隔符使附加命令被执行。
PocWriter 建议（未采纳，缺少端点 /026）：针对 026.php（第 10 行 sink）的 OS 命令注入 POC。注入点为请求参数 ip，被拼接进系统命令执行（CWE-78）。payload 使用 TARGET 占位符，仅作文本工件。
PocWriter 建议（未采纳，缺少端点 /026）：符合 CWE-78（OS Command Injection）。漏洞位于 026.php:10，外部输入来自请求参数 ip，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅限授权测试。目标地址统一使用 TARGET 占位符，需手动替换后由测试人员自行执行；管线不执行、不联网。注入通道为参数 ip，不要改为其他参数名。

### F-3: 026.php *nix 分支 ping -c 4 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`026.php:12-14`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入（026.php:5 读取并赋给 `$target`）。当 026.php:8 的平台判断不成立（非 Windows NT）时进入 026.php:12 的 else 分支，在 026.php:14 将 `$target` 直接拼接到 `'ping  -c 4 '` 之后交给 `shell_exec()`。代码片段中未见任何转义、白名单或参数化处理，`$target` 中的 shell 元字符（`;`、`|`、`&&`、`$()`、反引号等）会被 shell 解释执行。

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

远程未认证攻击者可在 *nix Web 服务器进程权限下执行任意系统命令，实现 RCE、读取敏感文件、建立持久化后门等，影响为服务器完全失陷。

**CVE / CWE 论证**

CWE-78（OS 命令注入）。外部可达性：注入点为 HTTP query 参数 `ip`，无需认证即可到达 026.php:14 的 `shell_exec`；利用链闭合：`ip` → `$target` → 字符串拼接 → `shell_exec`，无有效净化。该分支在非 Windows 平台生效，与 026.php:10 的 Windows 分支构成同一参数的两条注入路径。

**修复建议**

改用不经过 shell 的参数数组方式执行 ping（如 `proc_open` 传数组），或对 `$target` 使用 `escapeshellarg()` 并叠加 `filter_var($target, FILTER_VALIDATE_IP)` 白名单校验；限制 Web 进程权限，避免以高权限账户运行。

**验证说明**

静态证据：入口 ANY /026；source=query/ip；sink=026.php:14；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `026.php?ip=<payload>` → 026.php:5 将参数值写入 `$target` → 026.php:8 平台判断为假进入 else 分支 → 026.php:14 执行 `shell_exec('ping  -c 4 ' . $target)`，payload 中的命令分隔符导致附加命令被执行。
PocWriter 建议（未采纳，缺少端点 /026）：针对 026.php（第 14 行 sink）的 OS 命令注入 POC。注入点为请求参数 ip，被拼接进系统命令执行（CWE-78）。payload 使用 TARGET 占位符，仅作文本工件。
PocWriter 建议（未采纳，缺少端点 /026）：符合 CWE-78（OS Command Injection）。漏洞位于 026.php:14，外部输入来自请求参数 ip，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅限授权测试。目标地址统一使用 TARGET 占位符，需手动替换后由测试人员自行执行；管线不执行、不联网。注入通道为参数 ip，不要改为其他参数名。

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
| safety_guard | 安全防护 | 2.61 | 是 |
| surface_mapper | 攻击面测绘 | 7.76 | 是 |
| deep_finder | LLM 深挖 | 7.98 | 是 |
| candidate_screener | 候选筛选 | 4.57 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.33 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.29 | 是 |
| coordinator | 管线协调 | 6.66 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
