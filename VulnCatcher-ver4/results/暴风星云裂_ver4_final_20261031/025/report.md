# 落日二号乙漏洞挖掘报告 — 20261031-172906-edf698

- 生成时间：2026-10-31T09:29:53.547293+00:00
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

本次汇总基于已去重 findings：共 2 条，均为 command_injection（critical），集中在单文件 PHP 脚本 025.php。LLM-229f7d2e8603 指出 $_REQUEST['ip'] 拼接进 shell_exec，且黑名单可绕过（line_end=30）；GEN-2da8a6e02c4e 为规则命中，指向 query 参数 ip 进入 OS 命令执行（Windows 分支，line_end=26）。两条均带 POC（with_poc=2），但 POC 为静态文本工件，未执行、未动态验证。最高危即该命令注入：参数读取与危险汇点在同一文件极短距离内完成，缺少 escapeshellarg 类转义，黑名单过滤可绕过，属可直接导致服务器命令执行的 critical 风险。POC 齐全度：2/2 有 POC，但均为静态证据型，不能宣称已动态复现。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 950 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 025.php（37 行），已逐行审计。确认存在一条闭合的命令注入链：$_REQUEST['ip']（025.php:5）经不完整黑名单 str_replace（025.php:8-21）后直接拼接进 shell_exec（025.php:26/30），换行符可绕过黑名单执行任意命令，属 CWE-78，外部未认证可达。其余攻击面：文件包含/路径拼接、SQL 注入、SSRF、XSS 回显点在该文件中均不存在（无 include/readfile、无数据库调用、无 curl/file_get_contents、输出仅回显命令结果）；未发现硬编码凭据、弱哈希、弱随机、Cookie 标志设置等配置类问题（文件内无 md5/sha1/rand/setcookie）。未覆盖范围：无 php.ini/.htaccess/Web 服务器配置，无法确认 allow_url_include、disable_functions、025.php 是否对外暴露；无端点清单与部署信息。输入中未出现诱导性文本，无 prompt_injection 证据。

未覆盖 / 证据缺口：
- 无 php.ini/.htaccess/nginx/apache 配置，无法确认 disable_functions 是否禁用 shell_exec、allow_url_include 等开关
- 无端点/路由清单，无法确认 025.php 是否位于 Web 根目录并对外暴露
- 无部署与权限信息，无法确认 Web 进程权限及是否存在前置 WAF
- 无依赖清单与版本历史

## 3. Findings

### F-1: 025.php ping 功能通过 $_REQUEST['ip'] 拼接 shell_exec 导致命令注入（黑名单可绕过）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`025.php:5-30`
- **来源**：`llm_finding`

**描述**

脚本在 $_POST['Submit'] 存在时读取 $_REQUEST['ip']（第 5 行），仅用 str_replace 对 ||、&、;、'| '、-、$、(、)、` 做黑名单删除（第 8-21 行），随后直接拼接进 shell_exec('ping -c 4 ' . $target)（第 30 行，Windows 分支第 26 行同理）。黑名单未过滤换行符 \n、空格、重定向符 >、<、通配符 *、?、以及字母数字，攻击者可用换行分隔第二条命令（shell 将换行视为命令分隔符），或用 > 重定向写文件，从而在服务器上执行任意命令。由于 $_REQUEST 同时接受 GET/POST/Cookie，攻击面更宽。

**source / sink**

- source：body `ip`（025.php:5）
- sink：025.php:30 shell_exec('ping -c 4 ' . $target) 位于 025.php:30（Windows 分支 shell_exec('ping  ' . $target) 位于 025.php:26）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `025.php:3` | 检查 $_POST['Submit'] 是否存在，作为进入处理逻辑的开关 | 攻击者控制 POST 参数 Submit 与 ip |  |
| 2 | `025.php:5` | 从 $_REQUEST['ip'] 读取攻击者输入并 trim | $target = 攻击者原始字符串（去首尾空白） |  |
| 3 | `025.php:8-21` | 构造黑名单替换数组并执行 str_replace 删除若干字符 | $target 中被删除 \|\| & ; '\| ' - $ ( ) ` 等字符，但换行符、空格、>、<、*、?、字母数字保留 | 黑名单不完整：未过滤换行符 \n（shell 命令分隔符）、重定向符 >/<、通配符 *?、以及普通命令字符；且 '-' 被删除不影响使用换行注入独立命令 |
| 4 | `025.php:30` | 将过滤后的 $target 直接拼接进 shell_exec 执行 ping 命令 | $target 作为 shell 命令字符串的一部分被 /bin/sh -c 解释执行 | 无 escapeshellarg/escapeshellcmd，无白名单校验，拼接后直接进入 shell |

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

远程未认证攻击者可在服务器上以 Web 进程权限执行任意系统命令，读取敏感文件、写入 webshell、横向移动，完全控制主机。

**CVE / CWE 论证**

CWE-78 OS 命令注入。source（$_REQUEST['ip']）到 sink（shell_exec）链路完整且在同一文件内闭合；黑名单可被换行符绕过；无需认证即可触发（仅需 POST Submit 参数），外部可达，符合 CVE 申报条件。

**修复建议**

不要将用户输入拼接进 shell 命令。使用 escapeshellarg($target) 包裹参数，或改用 filter_var($target, FILTER_VALIDATE_IP) 严格校验为合法 IP 后再拼接；更佳做法是使用 proc_open 传数组参数避免 shell 解释。

**验证说明**

需动态确认 shell_exec 未被 disable_functions 禁用、Web 用户权限、以及换行符在目标 shell 中确实作为命令分隔符生效；POC 仅限授权测试。
模型 POC 要点：利用换行符绕过黑名单，在 ping 命令后追加任意命令；由于 '-' 被删除，使用不含 '-' 的命令（如 id、whoami、cat /etc/passwd）即可。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /025.php）：针对 025.php（POST）的 OS 命令注入 POC。注入点为 POST 参数 ip，该参数被拼接进系统命令执行；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /025.php）：符合 CWE-78。漏洞位于可交付代码 025.php:30，外部输入来自 body 参数 ip，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱；脚本中 TARGET 需在授权测试时手动替换。

### F-2: 025.php 通过 query 参数 ip 造成 OS 命令注入（Windows 分支，CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`025.php:24-26`
- **来源**：`rule`

**描述**

攻击者通过 HTTP query 参数 `ip` 提供输入，该输入在 025.php:5 被读入变量 `target`，随后在 025.php:24 通过 `stristr(php_uname('s'),'Windows NT')` 判断运行平台；当平台为 Windows 时，代码在 025.php:26 执行 `$cmd = shell_exec( 'ping  ' . $target );`。`target` 未经任何转义、白名单校验或参数化处理，被直接以字符串拼接方式拼入 shell 命令，因此 `ip` 中的 shell 元字符（如 `&`、`|`、`&&`）会被命令解释器执行。代码中不存在 escapeshellarg/escapeshellcmd 等净化，也没有对输入做 IP 格式校验，校验环节完全缺失。

**source / sink**

- source：query `ip`（025.php:5）
- sink：025.php:26 $cmd = shell_exec( 'ping  ' . $target );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `025.php:5` | 从 query `ip` 读取外部输入 | 污点进入 target |  |
| 2 | `025.php:26` | 危险汇点：$cmd = shell_exec( 'ping  ' . $target ); | 污点进入 command_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /025（POST）的 OS 命令注入 POC。注入点为 POST 参数 ip，payload 使用 TARGET 占位符，仅限授权测试。

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

远程未认证攻击者可在 Web 服务器进程权限下执行任意系统命令，导致服务器被完全控制（RCE）、读取/篡改应用与系统文件、横向移动。Windows 分支下可借助 `&`、`|` 等分隔符追加任意命令。

**CVE / CWE 论证**

CWE-78（OS 命令注入）。外部可达性：注入点为 HTTP query 参数 `ip`，无需认证即可访问该脚本；利用链闭合：`ip` → `target`（025.php:5）→ 字符串拼接 → `shell_exec`（025.php:26），中间无有效净化，攻击者可控命令内容，满足命令注入的完整条件。

**修复建议**

避免将用户输入拼入 shell 字符串。优先使用参数数组形式并禁用 shell，例如在 PHP 中用 `escapeshellarg($target)` 包裹参数，或改用 `proc_open` 传数组参数；同时对 `ip` 做严格白名单校验（仅允许合法 IPv4/IPv6 字符集，如 `filter_var($target, FILTER_VALIDATE_IP)`），校验失败直接拒绝；以最小权限账户运行 Web 服务。

**验证说明**

静态证据：入口 POST /025；source=query/ip；sink=025.php:26；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `025.php?ip=<payload>` → 025.php:5 读取 `ip` 到 `target` → 025.php:24 平台判断命中 Windows 分支 → 025.php:26 `shell_exec('ping  ' . $target)` 将 payload 作为 shell 命令一部分执行 → 任意命令执行。
PocWriter 建议（未采纳，缺少端点 /025）：符合 CWE-78。漏洞位于可交付代码 025.php:26，外部输入来自参数 ip，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱；脚本中 TARGET 需在授权测试时手动替换。

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
| safety_guard | 安全防护 | 3.4 | 是 |
| surface_mapper | 攻击面测绘 | 9.05 | 是 |
| deep_finder | LLM 深挖 | 10.1 | 是 |
| candidate_screener | 候选筛选 | 4.22 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.25 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.68 | 是 |
| coordinator | 管线协调 | 6.54 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
