# 落日二号乙漏洞挖掘报告 — 20261031-011905-dd35bc

- 生成时间：2026-10-30T17:19:46.551284+00:00
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

本次汇总基于单文件 PHP 项目（027.php，30 行）的已去重 findings。共交付 2 条 command_injection（CWE-78），严重度均为 critical：LLM-70df6c6c834b 指出 027.php 通过 $_REQUEST['ip'] 拼接后进入 shell_exec（第 24 行附近），GEN-2b40f95f1bb0 指出 Windows 分支 ping 命令拼接（第 19 行附近）。两条均带 POC，属 HTTP 型可复现文本工件（未执行、未动态验证）。最高危即这两条命令注入，可直接导致任意命令执行。POC 齐全度：2/2 有 POC，但均为静态构造文本，未经动态确认。其余类型（sql/xpath/ldap 注入、xss、path_traversal、ssrf、weak_crypto/weak_hash/weak_random/insecure_cookie/trust_boundary）本次无交付候选，且输入未提供 027.php 代码片段，无法据此断言其不存在。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 804 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 027.php（30 行），已全量逐行审计。确认一条闭合的命令注入链：$_REQUEST['ip']（027.php:5）经不完整黑名单 str_replace（027.php:8-14）后直接拼接进 shell_exec（027.php:19/23），结果回显于 027.php:27。黑名单仅过滤 '&&' 与 ';'，管道符、$()、反引号、换行等均可绕过，构成未认证 RCE。未发现 SQL/文件/反序列化/SSRF 等其他汇点；无 Cookie/session 写入，故无 insecure_cookie 候选；无 md5/sha1 或加密调用，weak_hash/weak_crypto 不成立；无 rand()/uniqid() 令牌生成，weak_random 不成立；无 X-Forwarded-* 等信任边界判断。输入未出现诱导性指令，无 prompt_injection 证据。

未覆盖 / 证据缺口：
- 无 HTTP 端点/路由清单，endpoint 按文件路径推断为 /027.php
- 无 php.ini 与部署配置，无法确认 disable_functions 是否禁用 shell_exec
- 无认证机制信息，按源码判断为无鉴权
- code_pack 之外文件视为不存在，未覆盖

## 3. Findings

### F-1: 027.php ping 功能通过 $_REQUEST['ip'] 拼接 shell_exec 导致命令注入

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`027.php:3-24`
- **来源**：`llm_finding`

**描述**

脚本在收到 POST 参数 Submit 后，从 $_REQUEST['ip'] 读取用户输入 $target，仅用 str_replace 删除 '&&' 与 ';' 两个黑名单字符串，随后直接拼接进 shell_exec('ping -c 4 ' . $target)（Windows 分支为 'ping ' . $target）。黑名单不覆盖管道符 |、命令替换 $()、反引号、换行符 %0a、后台符 &、以及 || 等，攻击者可在 ip 参数中注入任意系统命令，以 Web 服务进程权限执行，导致远程代码执行。

**source / sink**

- source：body `ip`（027.php:5）
- sink：027.php:24 shell_exec( 'ping  -c 4 ' . $target ) 与 shell_exec( 'ping  ' . $target )

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `027.php:3` | 检查 POST 参数 Submit 是否存在，作为进入处理逻辑的开关 | 请求进入处理分支 |  |
| 2 | `027.php:5` | 从 $_REQUEST['ip'] 读取攻击者可控输入赋给 $target | $target = 攻击者原始字符串 |  |
| 3 | `027.php:8-14` | 仅用黑名单删除 '&&' 与 ';'，其余 shell 元字符（\|、$()、反引号、换行、&、\|\|）原样保留 | $target 经不完整黑名单过滤，仍含可执行元字符 | 黑名单只覆盖 '&&' 和 ';'，未过滤管道符 \|、命令替换 $()、反引号、换行符、单个 & 与 \|\|，可绕过 |
| 4 | `027.php:17-24` | 根据操作系统选择命令模板，将 $target 直接字符串拼接后交给 shell_exec 执行 | 拼接为 'ping -c 4 ' + 恶意 payload，进入 shell 解析 | 无参数化、无 escapeshellarg/escapeshellcmd，直接拼接 |
| 5 | `027.php:27` | 命令执行结果回显到页面 <pre> 中，攻击者可直接读取命令输出 | 命令 stdout 回显给攻击者 |  |

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
- POC 目录：`poc/LLM-70df6c6c834b`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

未认证攻击者可在服务器上以 Web 服务进程权限执行任意系统命令，读取敏感文件、横向移动、植入后门，完全控制主机。

**CVE / CWE 论证**

CWE-78 OS 命令注入。外部 HTTP 可达、无需认证、source（$_REQUEST['ip']）到 sink（shell_exec）链路在 CODE PACK 内完整闭合，黑名单可被常见 shell 元字符绕过，属典型 CVE 级 RCE。

**修复建议**

不要将用户输入拼接进 shell 命令；改用 escapeshellarg() 对目标做严格转义，或使用白名单校验 IP 格式（filter_var($target, FILTER_VALIDATE_IP)），并避免使用 shell_exec 执行外部命令。

**验证说明**

需动态确认 Web 进程权限与 shell_exec 是否被 php.ini disable_functions 禁用；确认目标操作系统分支以选择对应 payload。源码层面链路已闭合。
模型 POC 要点：向 027.php 提交 Submit 与 ip 参数，利用管道符或命令替换绕过黑名单执行任意命令并回显
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /027.php）：针对 027.php 第 24 行的 OS 命令注入 POC。外部输入来自 POST body 参数 ip，未净化即进入命令执行汇点，payload 使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /027.php）：符合 CWE-78（OS 命令注入）。漏洞位于 027.php:24，外部输入来自 POST body 参数 ip，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标，禁止使用破坏性命令。

### F-2: 027.php Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`027.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入（027.php:5 读取该参数并赋给 `$target`）。当 `php_uname('s')` 返回包含 `Windows NT` 的字符串时，代码进入 Windows 分支（027.php:17-18），在 027.php:19 执行 `$cmd = shell_exec( 'ping  ' . $target );`，把未净化的 `$target` 直接拼接到 shell 命令字符串中。代码未对 `$target` 做任何白名单校验、转义（如 escapeshellarg/escapeshellcmd）或参数化处理，因此 `$target` 中的 shell 元字符（如 `&`、`|`、`;`、`&&`）会被 shell 解释，从而执行攻击者附加的命令。

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

远程命令执行（RCE）：攻击者可在 Web 服务器进程权限下执行任意系统命令，导致服务器被完全控制、敏感数据泄露、横向移动及持久化。无需认证即可通过单个 HTTP 请求触发。

**CVE / CWE 论证**

CWE-78（OS 命令注入）。外部可达性：注入点来自 HTTP 查询参数 `ip`，任何能访问该脚本的攻击者均可控制。无需认证：脚本未包含任何认证/授权检查。利用链闭合：`ip` 参数（027.php:5）→ `$target` → 字符串拼接进 `shell_exec('ping  ' . $target)`（027.php:19），中间无有效净化，污点直达危险汇点。

**修复建议**

不要将外部输入拼接进 shell 命令。优先使用参数数组形式并避免 shell 解释（如 PHP 的 `proc_open` 配合参数数组，或直接调用系统 API）。若必须调用 ping，应对 `$target` 做严格白名单校验（仅允许合法 IP/主机名正则，如 `^[a-zA-Z0-9.-]+$`），并使用 `escapeshellarg($target)` 转义；同时以最小权限运行 Web 进程，禁用不必要的危险函数。

**验证说明**

静态证据：入口 ANY /027；source=query/ip；sink=027.php:19；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `027.php?ip=<payload>` → 027.php:5 将 `ip` 赋给 `$target` → 027.php:17 判断为 Windows 环境 → 027.php:19 `shell_exec('ping  ' . $target)` 拼接执行 → shell 解释 payload 中的元字符 → 任意命令执行。
PocWriter 建议（未采纳，缺少端点 /027）：针对 027.php 第 19 行的 OS 命令注入 POC。外部输入来自 query 参数 ip，未净化即进入命令执行汇点，payload 使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /027）：符合 CWE-78。漏洞位于 027.php:19，外部输入来自 query 参数 ip，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标。

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
| safety_guard | 安全防护 | 2.59 | 是 |
| surface_mapper | 攻击面测绘 | 6.94 | 是 |
| deep_finder | LLM 深挖 | 8.64 | 是 |
| candidate_screener | 候选筛选 | 3.49 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.02 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.36 | 是 |
| coordinator | 管线协调 | 6.07 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
