# 落日二号乙漏洞挖掘报告 — 20261031-164322-2f2706

- 生成时间：2026-10-31T08:44:07.445901+00:00
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

本次汇总仅覆盖单文件 PHP 脚本 025.php（37 行），去重后共 2 条 findings，均为 command_injection（critical）：LLM-229f7d2e8603 指出 ping 功能通过 ip 参数进入命令拼接、黑名单可绕过（行至 30）；GEN-2da8a6e02c4e 为规则命中，指向 Windows 分支 ping 命令拼接（行至 26）。两条均带 POC，属 HTTP 型可复现文本工件（未执行、未动态验证）。最高危即该命令注入链：请求参数直达 shell 汇点，且存在黑名单绕过路径，若脚本对外可达则可导致任意命令执行。POC 齐全度为 2/2，但仅限命令注入一类；其余类型（SQL 注入、路径穿越/文件包含、XSS、弱哈希/弱加密/弱随机、Cookie 标志、信任边界）本次均未交付结论，需按档位与人工复核处理。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 950 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中的 025.php（37 行）。该文件为独立 PHP 脚本，从 $_REQUEST['ip'] 读取输入，经不完整黑名单 str_replace 过滤后直接拼入 shell_exec 执行 ping，构成可绕过的命令注入（CWE-78），已给出基于换行符绕过的 POC。未发现其他独立攻击面（无文件包含、SQL、反序列化、输出回显 XSS 等）。未覆盖范围：无 php.ini/Web 服务器配置、无端点清单、无依赖清单，无法确认 disable_functions、allow_url_include、脚本可达性与认证要求；code_pack 之外文件视为不存在。

未覆盖 / 证据缺口：
- 缺少 php.ini 与 Web 服务器配置，无法确认 shell_exec 是否被禁用及脚本可达性
- 无端点清单，无法确认访问路径与认证要求
- 无依赖清单，无法评估第三方组件 CVE
- 未提供部署操作系统信息，Windows/*nix 分支需动态确认

## 3. Findings

### F-1: 025.php ping 功能通过 ip 参数导致命令注入（黑名单可绕过）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`025.php:5-30`
- **来源**：`llm_finding`

**描述**

025.php 在收到 POST 参数 Submit 后，从 $_REQUEST['ip'] 读取用户输入并 trim，随后用 str_replace 按黑名单删除 ||、&、;、'| '、-、$、(、)、` 等字符，再把结果直接拼进 shell_exec('ping -c 4 ' . $target)（Windows 分支为 shell_exec('ping  ' . $target)）。黑名单只删除单个字符，未做转义或参数化，攻击者可用换行符（%0a）分隔命令，或用未被过滤的字符（如 >、<、空格、字母数字）构造任意命令，从而在服务器上执行任意系统命令。

**source / sink**

- source：body `ip`（025.php:5）
- sink：025.php:30 shell_exec('ping  -c 4 ' . $target) / shell_exec('ping  ' . $target)

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `025.php:3` | 检查 POST 参数 Submit 是否存在，存在则进入处理分支 | 请求进入处理逻辑 |  |
| 2 | `025.php:5` | 从 $_REQUEST['ip'] 读取攻击者可控输入并 trim | $target = 攻击者原始输入（仅去首尾空白） |  |
| 3 | `025.php:8-21` | 用黑名单 str_replace 删除 \|\|、&、;、'\| '、-、$、(、)、` 等字符 | $target 被删除部分字符，但换行符、>、<、空格、字母数字等仍保留 | 黑名单只覆盖少量字符，未过滤换行符 \n、重定向符 >/<、以及普通命令字符，可用换行分隔第二条命令绕过 |
| 4 | `025.php:26` | Windows 分支把 $target 拼进 shell_exec('ping  ' . $target) | $target 作为 shell 命令字符串的一部分 |  |
| 5 | `025.php:30` | *nix 分支把 $target 拼进 shell_exec('ping  -c 4 ' . $target) 并执行 | 拼接后的字符串交给 shell 执行，注入命令被执行 |  |

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
  --data 'ip=%3Bid&Submit=Submit'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/LLM-229f7d2e8603`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

未认证攻击者可在服务器上以 Web 服务进程权限执行任意系统命令，导致服务器完全失陷、数据泄露、横向移动。

**CVE / CWE 论证**

CWE-78 OS 命令注入。source（$_REQUEST['ip']）到 sink（shell_exec）链路完整，黑名单可被换行符等未过滤字符绕过，无需认证即可外部触发，符合 CVE 接受标准。

**修复建议**

不要拼接 shell 命令；使用 escapeshellarg() 对 $target 转义，或改用白名单校验 IP 格式（如 filter_var($target, FILTER_VALIDATE_IP)），并避免使用 shell_exec 执行外部命令。

**验证说明**

需动态确认 shell_exec 未被 disable_functions 禁用、Web 服务器可访问该脚本，以及实际操作系统分支（Windows/*nix）以确定 payload 细节。
模型 POC 要点：向 025.php 提交 ip 参数，利用换行符绕过黑名单，在 ping 命令后追加任意命令，并通过页面回显的 <pre> 获取命令输出。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /025.php）：针对 025.php 的 OS 命令注入 POC（CWE-78）。注入点为 POST 参数 ip，源码在 025.php:30 附近将 ip 拼入系统命令执行；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /025.php）：符合 CWE-78（OS 命令注入）。外部输入来自 POST body 的 ip 参数，在 025.php:30 附近未净化即拼入命令执行 sink，source→sink 链静态闭合，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。脚本中的 TARGET 需替换为授权测试实例；执行前确认 sink 函数与拼接方式，必要时调整 payload 的引号闭合与编码。

### F-2: 025.php Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`025.php:24-26`
- **来源**：`rule`

**描述**

攻击者通过 HTTP query 参数 `ip` 提供输入，该值在 025.php:5 被读入变量 `target`，随后在 025.php:24 通过 `stristr(php_uname('s'),'Windows NT')` 判断运行平台；当命中 Windows 分支时，025.php:26 执行 `$cmd = shell_exec( 'ping  ' . $target );`，将外部可控的 `target` 直接以字符串拼接方式拼入 shell 命令，未做任何转义、白名单或参数化处理。由于 `shell_exec` 会把整串交给系统 shell 解释，`target` 中的 `&`、`|`、`;`、`&&` 等元字符可截断/追加命令，导致任意命令执行。校验无效的原因：代码仅做平台判断，未对 `target` 做任何输入过滤或 `escapeshellarg` 处理。

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

远程未认证攻击者可在目标主机上以 Web 服务进程权限执行任意系统命令，读取/篡改文件、窃取凭据、横向移动，最终可导致服务器完全失陷（RCE）。

**CVE / CWE 论证**

CWE-78（OS 命令注入）。外部可达性：注入点为 HTTP query 参数 `ip`，无需认证即可访问该脚本；利用链闭合：`ip` → `target`（025.php:5）→ 字符串拼接 → `shell_exec`（025.php:26），中间无有效净化，攻击者可控命令分隔符即可执行任意命令。

**修复建议**

避免将外部输入拼入 shell 命令；改用参数数组形式（如 `proc_open`/`escapeshellarg` 包裹每个参数），并对 `ip` 做严格白名单校验（仅允许合法 IPv4/IPv6 字符集，如 `filter_var($target, FILTER_VALIDATE_IP)`），校验失败直接拒绝；同时以最小权限运行 Web 进程。

**验证说明**

静态证据：入口 POST /025；source=query/ip；sink=025.php:26；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `025.php?ip=TARGET` 并注入命令分隔符（如 `127.0.0.1 & whoami`）→ 025.php:5 读取 `ip` 到 `target` → 025.php:24 平台判断命中 Windows 分支 → 025.php:26 `shell_exec('ping  ' . $target)` 将注入内容交给 shell 执行 → 任意命令执行。
PocWriter 建议（未采纳，缺少端点 /025）：针对 025.php 的 OS 命令注入 POC（CWE-78）。注入点为 ip 参数，源码在 025.php:26 附近将输入拼入系统命令；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /025）：符合 CWE-78（OS 命令注入）。外部输入在 025.php:26 附近未净化即拼入命令执行 sink，source→sink 链静态闭合，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。TARGET 需替换为授权测试实例；若源码实际从 $_GET 取值，应将参数移至查询串并相应调整请求。

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
| safety_guard | 安全防护 | 3.92 | 是 |
| surface_mapper | 攻击面测绘 | 6.54 | 是 |
| deep_finder | LLM 深挖 | 8.17 | 是 |
| candidate_screener | 候选筛选 | 4.47 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.45 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 9.01 | 是 |
| coordinator | 管线协调 | 5.79 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
