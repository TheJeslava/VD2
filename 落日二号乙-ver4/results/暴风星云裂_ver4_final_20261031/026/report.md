# 落日二号乙漏洞挖掘报告 — 20261031-172906-43c359

- 生成时间：2026-10-31T09:29:54.701508+00:00
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

本次汇总基于已去重的 2 条 findings，均集中在单文件 PHP 脚本 026.php，类型均为 command_injection（CWE-78），严重度 critical：LLM-709cbd914c63 指向 $_REQUEST['ip'] 拼接进 shell_exec 的 ping 功能（第 14 行），GEN-a86a53dc898b 指向 Windows 分支 ping 命令拼接（第 10 行），两条为同一污点路径的不同表述/分支，均已附带 POC 文本（静态构造，未执行、未动态验证）。最高危即该命令注入，若脚本暴露于可达网络，等价于远程命令执行。POC 齐全度为 2/2，但均为文本工件，需在授权环境自行验证。覆盖面上仅审计了 1 个文件、0 个端点，无框架、无认证/会话文件，攻击面测绘中的 path_traversal/LFI、反射型 XSS、SQL 二次注入、配置实现类（weak_hash/weak_random/insecure_cookie/weak_crypto/trust_boundary）均未形成 findings，属未覆盖而非已排除。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 533 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 026.php（21 行），已完整审计。该脚本为典型 ping 命令注入示例：$_REQUEST['ip'] 未经任何过滤直接拼接到 shell_exec，构成未认证远程命令执行（CWE-78），链路在源码内完整闭合，置信度高。未发现 SQL 注入、文件包含、XSS（输出 $cmd 为命令结果非直接回显用户输入，且无 htmlspecialchars 但注入面已被命令注入覆盖）、弱哈希/弱随机/Cookie 标志等其它独立问题。surface_notes 中关于 weak_hash/weak_random/insecure_cookie/weak_crypto/trust_boundary 的线索在源码中均无对应实现，不成立。未提供 php.ini 等配置，disable_functions 是否禁用 shell_exec 需动态确认。

未覆盖 / 证据缺口：
- 无 php.ini/服务器配置，无法确认 shell_exec 是否被 disable_functions 禁用
- 无部署拓扑信息，无法确认是否暴露公网
- 仓库仅含单文件样本，实际系统可能更大

## 3. Findings

### F-1: 026.php ping 功能通过 $_REQUEST['ip'] 拼接 shell_exec 导致命令注入（RCE）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`026.php:5-14`
- **来源**：`llm_finding`

**描述**

脚本在收到 POST 参数 Submit 后，从 $_REQUEST['ip'] 读取用户输入 $target，未做任何白名单、转义或参数化处理，直接字符串拼接到 shell_exec('ping  ' . $target)（Windows 分支）或 shell_exec('ping  -c 4 ' . $target)（*nix 分支）。攻击者可通过在 ip 参数中注入 shell 元字符（如 ; | & ` $()）执行任意系统命令，获得服务器命令执行权限。

**source / sink**

- source：body `ip`（026.php:5）
- sink：026.php:14 shell_exec('ping  -c 4 ' . $target) / shell_exec('ping  ' . $target)

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `026.php:3` | 检查 POST 参数 Submit 是否存在，作为进入处理逻辑的开关 | 攻击者控制请求体，设置 Submit=1 即可进入分支 |  |
| 2 | `026.php:5` | 从 $_REQUEST['ip'] 读取用户输入到 $target，无任何过滤 | $target = 攻击者完全可控字符串 |  |
| 3 | `026.php:8` | 通过 php_uname('s') 判断操作系统，决定走 Windows 或 *nix 分支 | $target 保持不变，仅选择拼接模板 |  |
| 4 | `026.php:10` | Windows 分支将 $target 直接拼接到 ping 命令并交给 shell_exec | 'ping  ' . $target 形成完整 shell 命令字符串 |  |
| 5 | `026.php:14` | *nix 分支将 $target 直接拼接到 ping -c 4 命令并交给 shell_exec | 'ping  -c 4 ' . $target 形成完整 shell 命令字符串，注入的元字符被 shell 解释执行 |  |

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

未认证远程攻击者可在服务器上以 Web 进程权限执行任意系统命令，完全控制主机，读取/篡改数据，横向移动。

**CVE / CWE 论证**

CWE-78 OS 命令注入。外部 HTTP 可达、无需认证、source（$_REQUEST['ip']）到 sink（shell_exec）链路在 CODE PACK 内完整闭合，无任何净化环节。

**修复建议**

不要将用户输入拼接到 shell 命令。使用 escapeshellarg() 对 $target 转义，或改用白名单校验（如 filter_var($target, FILTER_VALIDATE_IP)）后再拼接；更佳做法是使用 proc_open 传参数数组避免 shell 解释。

**验证说明**

源码链路完整闭合，可直接构造 POC。动态验证需确认目标 OS 分支与 shell_exec 是否被 disable_functions 禁用；若被禁用则影响降级。
模型 POC 要点：向 026.php 提交 Submit 与含 shell 元字符的 ip 参数，使 shell_exec 执行附加命令并回显到 <pre> 中
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /026.php）：针对 026.php（POST）的 OS 命令注入 POC。注入点为 POST 参数 ip，该参数被拼接进系统命令执行；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /026.php）：符合 CWE-78（OS 命令注入）。漏洞位于 026.php:14，外部输入来自 POST body 的 ip 参数，source→sink 链静态闭合且未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭沙箱。执行前将 TARGET 替换为授权测试目标；Content-Length 需按实际请求体长度调整。

### F-2: 026.php Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`026.php:8-10`
- **来源**：`rule`

**描述**

攻击者通过 HTTP query 参数 `ip` 提供输入，026.php:5 将其读入 `$target`；026.php:8 用 `stristr(php_uname('s'),'Windows NT')` 判断运行平台，命中 Windows 分支后，026.php:10 执行 `$cmd = shell_exec( 'ping  ' . $target );`。`$target` 未经任何转义、白名单校验或参数化，直接以字符串拼接方式进入 shell 命令行，因此 `&`、`|`、`&&` 等 Windows shell 元字符可截断 ping 命令并追加任意命令。代码片段中未见 escapeshellarg/escapeshellcmd 或输入白名单，校验缺失即为绕过原因。

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

远程命令执行（RCE）：攻击者以 Web 服务进程权限在目标主机执行任意系统命令，可读取/篡改应用与系统文件、窃取数据库与配置凭据、建立持久化后门，并可作为横向移动跳板。无需认证即可通过单个 GET 请求触发。

**CVE / CWE 论证**

CWE-78（OS Command Injection）：外部可控输入 `ip` 经 `$target` 未净化拼接进 `shell_exec`，形成完整 source→sink 链；该脚本为 Web 可达 PHP 页面，攻击者仅需构造 query 参数即可触发，无需认证、无需本地访问，利用链闭合。

**修复建议**

不要用 shell 拼接执行 ping：改用参数数组形式（如 proc_open/exec 传数组）或 PHP 原生网络函数；若必须调用外部程序，对 `$target` 做严格白名单校验（仅允许 IPv4/IPv6 字面量，用 filter_var(FILTER_VALIDATE_IP) 校验）并配合 escapeshellarg；同时以最小权限账户运行 Web 服务，禁用不必要的 shell 函数。

**验证说明**

静态证据：入口 POST /026；source=query/ip；sink=026.php:10；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：HTTP GET 请求携带 query 参数 `ip` → 026.php:5 赋值给 `$target` → 026.php:8 平台判断进入 Windows 分支 → 026.php:10 `shell_exec('ping  ' . $target)` 字符串拼接执行 → 注入的 shell 元字符使攻击者命令在服务器上执行。
PocWriter 建议（未采纳，缺少端点 /026）：针对 026（POST）的 OS 命令注入 POC。注入点为 POST 参数 ip，该参数被拼接进系统命令执行；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /026）：符合 CWE-78（OS 命令注入）。漏洞位于 026.php:10，外部输入来自 ip 参数，source→sink 链静态闭合且未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭沙箱。执行前将 TARGET 替换为授权测试目标；Content-Length 需按实际请求体长度调整。

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
| safety_guard | 安全防护 | 3.57 | 是 |
| surface_mapper | 攻击面测绘 | 9.09 | 是 |
| deep_finder | LLM 深挖 | 7.58 | 是 |
| candidate_screener | 候选筛选 | 4.02 | 是 |
| vulnerability_analyzer | 漏洞分析 | 8.51 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.36 | 是 |
| coordinator | 管线协调 | 6.78 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
