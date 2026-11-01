# 落日二号乙漏洞挖掘报告 — 20261031-164406-fcc67e

- 生成时间：2026-10-31T08:44:53.017753+00:00
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

本次汇总基于已去重 findings：共 2 条，均为 command_injection（critical），集中在单文件 PHP 脚本 027.php。LLM-ee1cf990d74d 指出 ping 功能通过 ip 参数拼接命令，黑名单仅过滤 && 与 ;，可绕过；GEN-2b40f95f1bb0 指出 Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）。两条均带 POC（HTTP 型，命令注入可通过请求参数触发），最高危即这两条 critical 命令注入。POC 齐全度：2/2 有 POC，但均为静态构造文本，未做动态验证。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 804 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 027.php（30 行，已全量审计 1-30 行）。该脚本为无框架过程式页面：入口为 $_REQUEST['ip']（第 5 行），经不完整黑名单 str_replace（第 8-14 行，仅过滤 '&&' 与 ';'）后直接拼接进 shell_exec（第 19、23 行），构成闭合的命令注入 RCE 链，已作为唯一 finding 交付。其余候选：weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 在该文件中均无对应代码证据（无 md5/sha1、无加密调用、无 rand/mt_rand、无 setcookie、无 X-Forwarded-For/REMOTE_ADDR 信任逻辑），故不报告。第 27 行 $html 拼接 $cmd 属命令输出回显，非独立 XSS 源（$cmd 为命令结果，非直接用户输入反射），未单独立项。未覆盖范围：无 php.ini/Web 服务器配置、无 composer.json、无路由与鉴权信息，无法确认部署 URL、disable_functions 与访问控制；输入中未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- 缺少 php.ini 与 Web 服务器配置，无法确认 shell_exec 是否被禁用及运行用户权限
- 无路由/鉴权信息，无法确认该脚本实际暴露路径与访问控制
- 无依赖清单与 README，运行环境版本未知

## 3. Findings

### F-1: 027.php ping 功能通过 ip 参数导致命令注入（黑名单仅过滤 && 与 ;）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`027.php:5-23`
- **来源**：`llm_finding`

**描述**

脚本在收到 POST 参数 Submit 后，从 $_REQUEST['ip'] 读取用户输入 $target，仅用 str_replace 删除 '&&' 与 ';' 两个子串，随后直接拼接进 shell_exec('ping -c 4 ' . $target)（Windows 分支为 shell_exec('ping  ' . $target)）。黑名单未覆盖管道符 |、命令替换 $() 与反引号、换行符、后台符 &、以及 || 等，攻击者可在 ip 参数中注入任意系统命令并以 Web 进程权限执行，形成完整 RCE。

**source / sink**

- source：body `ip`（027.php:5）
- sink：027.php:23 shell_exec('ping  -c 4 ' . $target)（第 23 行）与 shell_exec('ping  ' . $target)（第 19 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `027.php:3` | 仅校验 POST 中存在 Submit 字段即进入处理分支，无身份校验 | 请求进入处理逻辑 |  |
| 2 | `027.php:5` | 从 $_REQUEST['ip'] 读取攻击者可控字符串到 $target | $target = 攻击者原始输入 |  |
| 3 | `027.php:8-14` | 黑名单仅含 '&&' 与 ';'，str_replace 删除这两个子串 | $target 中 '&&' 与 ';' 被移除，其余字符（\|、$()、`、\n、&、\|\|）原样保留 | 黑名单不完整：未过滤管道符 \|、命令替换 $() 与反引号、换行、单个 & 与 \|\|，可用这些分隔符注入命令 |
| 4 | `027.php:17-24` | 根据 php_uname 判断系统后，将 $target 直接字符串拼接进 shell_exec 的 ping 命令 | $target 作为 shell 命令的一部分被 shell 解释执行 |  |
| 5 | `027.php:27` | 命令输出被拼入 $html 并回显，攻击者可直接看到命令执行结果 | 命令 stdout 回显给攻击者 |  |

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
  --data 'ip=%3Bid&Submit=Submit'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/LLM-ee1cf990d74d`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

未认证远程攻击者可在服务器上以 Web 进程权限执行任意系统命令，读取敏感文件、横向移动、植入后门，完全控制主机。

**CVE / CWE 论证**

CWE-78 OS 命令注入。外部可达（HTTP POST 参数 ip），无需认证，source→sink 链路在 027.php 内闭合，黑名单可被 |、$()、反引号等轻易绕过，属典型 CVE 级 RCE。

**修复建议**

不要将用户输入拼接进 shell 命令；使用 escapeshellarg() 对 $target 转义，或改用白名单校验（仅允许合法 IP/主机名正则），并优先使用参数化方式（如 proc_open 传数组参数）避免经过 shell。

**验证说明**

需动态确认 shell_exec 未被 disable_functions 禁用、Web 进程权限，以及目标操作系统分支；源码层面链路已完整闭合。
模型 POC 要点：向 027.php 提交 Submit 与 ip 参数，利用管道符或命令替换绕过黑名单执行任意命令并读取回显
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。

### F-2: 027.php Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`027.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入（027.php:5 读取该参数并赋给 $target）。程序未对 $target 做任何白名单、转义或参数化处理，在 Windows 分支（php_uname('s') 含 'Windows NT' 时，027.php:17）直接将其拼接到 shell 命令字符串中：027.php:19 `$cmd = shell_exec( 'ping  ' . $target );`。由于 shell_exec 通过系统 shell 执行，拼接进命令的 `&`、`|`、`&&`、`;`（Windows 下 cmd 语义）等元字符会被解释为命令分隔符，从而执行攻击者附加的任意命令。校验无效的原因：代码中不存在 escapeshellarg/escapeshellcmd、不存在 IP 格式校验、不存在命令参数数组形式调用，污点从 027.php:5 直达 027.php:19 汇点。

**source / sink**

- source：query `ip`（027.php:5）
- sink：027.php:19 $cmd = shell_exec( 'ping  ' . $target );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `027.php:5` | 从 query `ip` 读取外部输入 | 污点进入 target |  |
| 2 | `027.php:19` | 危险汇点：$cmd = shell_exec( 'ping  ' . $target ); | 污点进入 command_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /027（POST）的 OS 命令注入 POC。注入点：POST 参数 ip；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/027'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 OS 命令注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/027' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'ip=%3Bid&Submit=Submit'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/GEN-2b40f95f1bb0`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

远程命令执行（RCE）：攻击者无需认证即可在 Web 服务器进程权限下执行任意系统命令，可读取/篡改应用与系统文件、窃取数据库凭据、横向移动，完全失陷主机。

**CVE / CWE 论证**

CWE-78（OS Command Injection）。外部可达性：入口为 HTTP query 参数 `ip`，属公网可访问的 Web 端点；无需认证：代码片段中未见任何鉴权/会话校验；利用链闭合：027.php:5 读取 `ip` → $target → 027.php:19 shell_exec 字符串拼接，中间无净化，攻击者可控命令分隔符即可闭合利用链。

**修复建议**

1) 不要用 shell 拼接：改用参数数组形式，如 `exec('ping', [$target])`（PHP 8+ 的 proc_open 数组形式）或直接使用 PHP 原生网络函数（如 `gethostbyname`/socket）替代调用系统 ping；2) 若必须调用外部程序，对 $target 做严格白名单校验（仅允许 IPv4/IPv6 字面量，用 `filter_var($target, FILTER_VALIDATE_IP)`），并配合 `escapeshellarg()`；3) 以最小权限运行 Web 进程，禁用不必要的危险函数（disable_functions 中限制 shell_exec/exec/system）。

**验证说明**

静态证据：入口 POST /027；source=query/ip；sink=027.php:19；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `GET /027.php?ip=127.0.0.1%20%26%26%20<任意命令>`；027.php:5 将 `ip` 值写入 $target；在 Windows 主机上进入 027.php:17 分支；027.php:19 将 $target 原样拼入 `ping  ` 命令并交给 shell_exec 执行，shell 解析 `&&` 后执行攻击者附加命令，命令输出经 $cmd 返回，形成完整 RCE 链。

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
| safety_guard | 安全防护 | 3.75 | 是 |
| surface_mapper | 攻击面测绘 | 7.06 | 是 |
| deep_finder | LLM 深挖 | 8.7 | 是 |
| candidate_screener | 候选筛选 | 4.03 | 是 |
| vulnerability_analyzer | 漏洞分析 | 9.5 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 9.2 | 否 |
| coordinator | 管线协调 | 4.73 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
