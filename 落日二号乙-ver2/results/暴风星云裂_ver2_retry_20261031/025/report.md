# 落日二号乙漏洞挖掘报告 — 20261031-002053-7b0f5e

- 生成时间：2026-10-30T16:21:42.720014+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\025.zip`
- 输入模式：`zip`
- SHA256：`66af849b3e4604c64e51a3ebfe871ee7f6288606b9cdb1f87c1c6314d29cc49e`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`high`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总基于已去重 findings：共 2 条，均为 command_injection（critical），集中在单文件 PHP 脚本 025.php。LLM-229f7d2e8603 指出 ping 工具页 ip 参数的黑名单过滤可被绕过，最终进入 shell_exec；GEN-2da8a6e02c4e 指出 Windows 分支 ping 命令字符串拼接导致 OS 命令注入（CWE-78）。两条均带 POC（has_poc=true），但 POC 为静态构造文本，未做动态验证。最高危即这两条 critical 命令注入，属同一汇点的重复视角（LLM 与规则各一），建议合并为一条交付并保留双证据。POC 齐全度：2/2 有 POC，但均为静态 POC，不能宣称可动态复现。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 950 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 025.php（37 行），已逐行审计。发现一条闭合的命令注入链：$_REQUEST['ip']（第5行）经不完整黑名单 str_replace（第8-21行）后直接拼接进 shell_exec（第26/30行），可用换行符、重定向符、单独管道符绕过，构成 CWE-78 命令注入。第34行 $html .= "<pre>{$cmd}</pre>" 将命令输出回显，属命令执行结果的展示，不单独构成 XSS（$cmd 为命令输出而非直接用户输入，且未做 HTML 转义，但主要风险已被命令注入覆盖）。未发现数据库操作、文件包含、反序列化、SSRF、弱加密/弱随机/硬编码密钥等其它可利用链。surface_notes 中提到的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 在本文件中均无对应代码，不成立。

未覆盖 / 证据缺口：
- 无端点清单，实际 URL 与方法需人工确认
- 无 php.ini/disable_functions 配置，无法确认 shell_exec 是否可用
- 无部署与网络暴露信息，无法确认是否公网可达
- 无框架/依赖清单，无法评估第三方组件 CVE

## 3. Findings

### F-1: 025.php ping 工具页 ip 参数黑名单过滤可绕过导致 shell_exec 命令注入

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`025.php:5-30`
- **来源**：`llm_finding`

**描述**

025.php 在收到 POST 参数 Submit 后，从 $_REQUEST['ip'] 读取用户输入（第5行），仅用 str_replace 做黑名单替换（第8-21行），随后直接拼接进 shell_exec('ping -c 4 ' . $target)（第30行，Windows 分支为第26行）。黑名单只过滤了 ||、&、;、'| '、-、$、(、)、` 等字符，未过滤换行符 \n、空格、重定向符 >、<、以及未被列入的管道符 '|'（注意黑名单里是 '| ' 带空格，单独的 '|' 不在其中）。攻击者可用换行符或空格+重定向/管道构造任意命令执行，属于典型的 OS 命令注入（CWE-78）。

**source / sink**

- source：body `ip`（025.php:5）
- sink：025.php:30 shell_exec('ping  -c 4 ' . $target) 第30行（Windows 分支 shell_exec('ping  ' . $target) 第26行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `025.php:3` | 检测到 POST 参数 Submit 存在，进入处理分支 | 请求进入处理逻辑 |  |
| 2 | `025.php:5` | 从 $_REQUEST['ip'] 读取攻击者可控输入并 trim | 原始字符串，攻击者完全可控 |  |
| 3 | `025.php:8-21` | 用 str_replace 对黑名单字符做删除替换 | 仅删除 \|\|、&、;、'\| '、-、$、(、)、` 等字符；换行符、空格、>、<、单独 '\|' 未被过滤 | 黑名单不完整：未过滤换行符 \n、重定向符 >/<、单独管道符 '\|'，且 str_replace 只做一次性替换，可用换行或空格+重定向绕过 |
| 4 | `025.php:30` | 将过滤后的 $target 拼接进 shell_exec 执行 ping 命令 | 拼接进 shell 命令字符串，作为 shell 解释执行 | 无参数化、无 escapeshellarg/escapeshellcmd，直接字符串拼接 |

**POC**

针对 /025.php（POST）的 OS 命令注入 POC。注入点为 POST 参数 ip，该参数被拼接进系统命令执行；payload 使用 TARGET 占位符，仅限授权测试。

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

未授权远程攻击者可在服务器上以 Web 进程权限执行任意系统命令，读取敏感文件、写入 webshell、横向移动，完全控制主机。

**CVE / CWE 论证**

CWE-78 OS 命令注入。外部可达（HTTP POST），无需认证，source→sink 链完整闭合，黑名单可被换行符/重定向符绕过，属高危可利用漏洞。

**修复建议**

不要将用户输入拼接进 shell 命令；使用 escapeshellarg() 对参数转义，或改用白名单校验 IP 格式（filter_var($ip, FILTER_VALIDATE_IP)），并避免使用 shell_exec 执行外部命令。

**验证说明**

需确认部署环境 shell_exec 未被 disable_functions 禁用、目标 OS 类型；换行符注入在 *nix 下有效，Windows 下可用 & 之外的方式（如换行）验证。
模型 POC 要点：利用换行符绕过黑名单，在 ping 命令后追加任意命令执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /025.php）：符合 CWE-78（OS 命令注入）。漏洞位于可交付代码 025.php:30，外部输入来自 POST body 参数 ip，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：脚本仅为文本工件，不执行、不联网；使用前将 TARGET 替换为授权目标。request.http 中 Content-Length 对应 body 'ip=%3Bid'（8 字节）。

### F-2: 025.php Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`025.php:24-26`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入（025.php:5 读取到 `$target`），该值未经任何转义或白名单校验，在 Windows 分支（`stristr(php_uname('s'),'Windows NT')` 为真，025.php:24）被直接字符串拼接到 `shell_exec('ping  ' . $target)`（025.php:26）。由于拼接发生在 shell 解释之前，`$target` 中的 `&`、`|`、`&&`、`;`（Windows cmd 下 `&`/`|`/`&&`）等元字符会被 shell 解释为命令分隔符，从而执行攻击者附加的任意命令。代码中不存在 escapeshellarg/escapeshellcmd、白名单或输入格式校验，因此校验完全缺失。

**source / sink**

- source：query `ip`（025.php:5）
- sink：025.php:26 $cmd = shell_exec( 'ping  ' . $target );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `025.php:5` | 从 query `ip` 读取外部输入 | 污点进入 target |  |
| 2 | `025.php:26` | 危险汇点：$cmd = shell_exec( 'ping  ' . $target ); | 污点进入 command_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /025（ANY 方法）的 OS 命令注入 POC。注入点为查询参数 ip，被拼接进系统命令执行；payload 使用 TARGET 占位符，仅限授权测试。

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

CWE-78（OS 命令注入）。外部可达性：入口为 HTTP query 参数 `ip`，无需认证；利用链闭合：`ip` → `$target`（025.php:5）→ 字符串拼接 → `shell_exec`（025.php:26），中间无净化，攻击者可用 `127.0.0.1 & whoami` 之类载荷闭合注入。该分支仅在 Windows 主机触发，属环境相关可达性，但一旦命中即完整可利用。

**修复建议**

不要通过 shell 拼接执行 ping：使用 `proc_open`/`exec` 的数组形式（如 `exec('ping', ['-n','4',$target])`）避免 shell 解析；同时对 `$target` 做严格白名单校验（仅允许 IPv4/IPv6 字面量，使用 `filter_var($target, FILTER_VALIDATE_IP)`），拒绝含空白与 shell 元字符的输入；以最小权限运行 Web 进程。

**验证说明**

静态证据：入口 ANY /025；source=query/ip；sink=025.php:26；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `025.php?ip=127.0.0.1%20%26%26%20whoami`；025.php:5 将 `ip` 赋给 `$target`；025.php:24 判定为 Windows 后进入 025.php:26，`shell_exec('ping  ' . $target)` 实际执行 `ping  127.0.0.1 && whoami`，第二条命令由 cmd 执行，输出回显给攻击者。
PocWriter 建议（未采纳，缺少端点 /025）：符合 CWE-78（OS 命令注入）。漏洞位于可交付代码 025.php:26，外部输入来自查询参数 ip，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：脚本仅为文本工件，不执行、不联网；使用前将 TARGET 替换为授权目标。ANY 表示方法不限，实际测试建议用 GET 或 POST 均可触发查询参数读取。

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
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.82 | 是 |
| surface_mapper | 攻击面测绘 | 11.4 | 是 |
| deep_finder | LLM 深挖 | 8.75 | 是 |
| candidate_screener | 候选筛选 | 4.53 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.42 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.94 | 是 |
| coordinator | 管线协调 | 5.89 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
