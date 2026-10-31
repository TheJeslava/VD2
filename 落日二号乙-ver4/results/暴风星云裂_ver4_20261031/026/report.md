# 落日二号乙漏洞挖掘报告 — 20261031-164328-c353b1

- 生成时间：2026-10-31T08:44:16.640189+00:00
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

本次汇总基于单文件 PHP 脚本 026.php（21 行）的静态审计结果，共交付 2 条去重后的发现，均为 command_injection（CWE-78），严重度 critical：LLM-709cbd914c63 指出 $_REQUEST['ip'] 被拼接进 shell_exec 形成 RCE（026.php 第 14 行附近），GEN-a86a53dc898b 指出 Windows 分支 ping 命令拼接导致 OS 命令注入（026.php 第 10 行附近）。两条发现均带 POC，但 POC 为静态文本工件（TARGET 占位、仅限授权测试），本次未执行、未搭建沙箱、未做动态验证，因此不能宣称已动态复现。最高危项是 026.php 中未过滤的请求参数直达 shell_exec 的命令注入，可直接导致远程命令执行。POC 齐全度：2/2 有 POC，但均为静态证据型。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 533 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 026.php（21 行）。已逐行审计：第 3 行以 POST Submit 为开关，第 5 行从 $_REQUEST['ip'] 取输入，第 8 行判断 OS，第 10/14 行将输入直接拼接进 shell_exec，第 18 行回显。确认存在一条闭合的命令注入链（CWE-78），无需认证即可 RCE。其余 medium_review_items（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary/hardcoded_secret）在文件中均无对应代码（无 md5/sha1、无加解密、无随机数、无 setcookie、无硬编码凭据），不成立。未发现 prompt_injection 文本。未覆盖：无 php.ini/部署配置，无法确认运行时设置；但命令注入不依赖这些配置。

未覆盖 / 证据缺口：
- 无 php.ini/.htaccess/Web 服务器配置，无法确认 allow_url_include 等运行时设置（不影响本命令注入结论）
- 无路由/鉴权配置，无法确认实际 URL 映射与访问控制
- 未做动态验证，OS 分支与 shell 环境需人工确认

## 3. Findings

### F-1: 026.php ping 功能通过 $_REQUEST['ip'] 拼接 shell_exec 导致命令注入（RCE）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`026.php:5-14`
- **来源**：`llm_finding`

**描述**

026.php 在收到 POST 参数 Submit 后，直接从 $_REQUEST['ip'] 读取用户输入并赋值给 $target，未做任何白名单、转义（escapeshellarg/escapeshellcmd）或格式校验，随后在第 10 行（Windows 分支）与第 14 行（*nix 分支）将 $target 直接字符串拼接到 shell_exec('ping ...' . $target) 中执行。攻击者可通过在 ip 参数中注入 shell 元字符（如 ; | & $() 反引号）在服务器上执行任意系统命令，获得远程代码执行。

**source / sink**

- source：body `ip`（026.php:5）
- sink：026.php:14 shell_exec('ping -c 4 ' . $target) / shell_exec('ping  ' . $target)

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `026.php:3` | 检查 POST 参数 Submit 是否存在，作为进入处理逻辑的开关 | 请求进入处理分支 |  |
| 2 | `026.php:5` | 从 $_REQUEST['ip'] 读取攻击者可控输入并赋给 $target，无任何过滤 | $target = 原始用户输入 | 无白名单/无 escapeshellarg/无类型校验 |
| 3 | `026.php:8` | 通过 php_uname('s') 判断操作系统，选择对应分支（不影响注入） | 分支选择 |  |
| 4 | `026.php:14` | 将 $target 直接拼接到 ping 命令字符串并交给 shell_exec 执行（*nix 分支；Windows 分支见第 10 行） | 命令字符串 'ping -c 4 ' . $target 交由 /bin/sh 解析 | shell 元字符未被转义，直接由 shell 解释执行 |

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
  --data 'ip=%3Bid&Submit=Submit'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/LLM-709cbd914c63`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

未认证远程攻击者可在 Web 服务器进程权限下执行任意系统命令，完全控制主机，读取敏感文件、横向移动。

**CVE / CWE 论证**

CWE-78 OS 命令注入。source（$_REQUEST['ip']）到 sink（shell_exec 字符串拼接）链路完整闭合，无任何过滤，外部无需认证即可触发，属典型 RCE。

**修复建议**

不要将用户输入拼接进 shell 命令；使用 escapeshellarg($target) 转义，或改用参数数组形式（如 proc_open 传数组），并对 ip 做严格 IP 格式校验（filter_var FILTER_VALIDATE_IP）。

**验证说明**

静态链路完整；动态验证需确认目标 OS 分支与 shell 环境，但两分支均存在注入，不影响结论。
模型 POC 要点：向 026.php 提交 Submit 与含 shell 元字符的 ip 参数，使 shell_exec 在 ping 命令后追加执行任意命令，命令输出经 $cmd 回显到页面 <pre> 中。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /026.php）：针对 026.php 的 OS 命令注入 POC（CWE-78）。注入点为 POST 表单参数 ip，源码在 026.php:14 附近将 ip 拼入系统命令执行；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /026.php）：符合 CWE-78（OS 命令注入）。漏洞位于可交付代码 026.php:14，外部输入来自 POST body 参数 ip，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。目标地址统一使用 TARGET 占位符，仅限授权测试。请求结构沿用输入中的确定性 POC，仅补充基线与状态确认步骤。

### F-2: 026.php Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`026.php:8-10`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入，该参数在 026.php:5 被读入变量 `target`。026.php:8 使用 `stristr(php_uname('s'), 'Windows NT')` 判断运行平台，命中 Windows 分支后，026.php:10 执行 `$cmd = shell_exec( 'ping  ' . $target );`，将 `target` 未经任何转义、白名单校验或参数化直接拼接到 shell 命令字符串中。由于 `shell_exec` 会把整串交给系统 shell 解析，`target` 中的 `&`、`|`、`&&`、`;`（Windows cmd 下为 `&`、`|`、`&&`）等元字符会被解释为命令分隔符，从而在 Web 进程权限下执行任意命令。代码中不存在 escapeshellarg/escapeshellcmd、正则白名单或 IP 格式校验，因此校验完全缺失。

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

远程未认证攻击者可在目标主机上以 Web 服务进程权限执行任意系统命令，导致服务器完全失陷：读取任意文件与配置、窃取数据库凭据、写入 WebShell、横向移动。属于 RCE 级别影响。

**CVE / CWE 论证**

CWE-78（OS 命令注入）。外部可达性：注入点为 HTTP query 参数 `ip`，无需认证即可访问 026.php。利用链闭合：`ip` → `target`（026.php:5）→ 字符串拼接（026.php:10）→ `shell_exec` 执行。校验无效原因：全程无转义、无白名单、无类型约束，shell 元字符直接生效。该分支仅在 Windows 主机触发，属环境相关但代码路径确定。

**修复建议**

不要通过 shell 拼接执行 ping。改用参数数组形式并禁用 shell，例如 PHP 中用 `proc_open` 传入参数数组，或直接使用 `filter_var($target, FILTER_VALIDATE_IP)` 严格校验为合法 IP 后再以数组参数调用；对输入做白名单（仅允许 IPv4/IPv6 字面量），拒绝包含任何 shell 元字符的输入；以最小权限账户运行 Web 服务。

**验证说明**

静态证据：入口 POST /026；source=query/ip；sink=026.php:10；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `026.php?ip=TARGET` 并在 `ip` 中注入命令分隔符与附加命令 → 026.php:5 将参数值赋给 `target` → 026.php:8 平台判断进入 Windows 分支 → 026.php:10 将 `target` 拼入 `ping  ` 命令串 → `shell_exec` 交由 cmd 解析执行，附加命令以 Web 进程权限运行。
PocWriter 建议（未采纳，缺少端点 /026）：针对 026.php 的 OS 命令注入 POC（CWE-78）。注入点为 POST 表单参数 ip，源码在 026.php:10 附近将 ip 拼入系统命令执行；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /026）：符合 CWE-78（OS 命令注入）。漏洞位于可交付代码 026.php:10，外部输入来自 POST body 参数 ip，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。目标地址统一使用 TARGET 占位符，仅限授权测试。输入中 endpoint 标注为 query 但请求方法为 POST，此处按源码 POST 参数 ip 构造，需补充源码确认取值方式。

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
| safety_guard | 安全防护 | 3.43 | 是 |
| surface_mapper | 攻击面测绘 | 8.76 | 是 |
| deep_finder | LLM 深挖 | 7.49 | 是 |
| candidate_screener | 候选筛选 | 3.56 | 是 |
| vulnerability_analyzer | 漏洞分析 | 9.25 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 10.16 | 是 |
| coordinator | 管线协调 | 5.88 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
