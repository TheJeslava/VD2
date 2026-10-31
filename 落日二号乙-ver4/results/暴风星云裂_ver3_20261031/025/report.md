# 落日二号乙漏洞挖掘报告 — 20261031-010117-c672a3

- 生成时间：2026-10-30T17:02:03.089762+00:00
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

本次汇总基于已去重 findings：共 2 条，均为 command_injection（critical），集中在单文件 025.php。LLM-229f7d2e8603 指出 025.php 第 30 行附近通过 $_REQUEST['ip'] 进入 ping 功能，黑名单过滤可绕过；GEN-2da8a6e02c4e 为规则命中，指向第 26 行 Windows 分支 ping 命令拼接（CWE-78）。两条均标记 has_poc=true，POC 为文本工件（TARGET 占位，仅限授权测试），未执行、未动态验证。最高危即该命令注入：source→sink 路径极短，若脚本面向可达网络则风险为 critical。POC 覆盖 2/2 findings，但均为静态构造，动态可利用性未验证。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 950 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 025.php（37 行，全文可见）。审计确认存在一条闭合的命令注入链：$_REQUEST['ip']（025.php:5）经不完整黑名单 str_replace（025.php:8-21）后直接拼接进 shell_exec（025.php:26/30），黑名单未过滤换行符、单个管道符、重定向符，且顺序替换可被嵌套构造绕过，构成未授权远程命令执行。其余攻击面：脚本无数据库、无文件包含、无 unserialize/eval、无会话/Cookie 逻辑、无硬编码凭据，故 weak_hash/weak_random/weak_crypto/insecure_cookie/hardcoded_secret 等配置型候选在本文件中无证据支撑，未报告。未覆盖范围：无 php.ini/Web 服务器配置、无端点清单与部署信息，无法确认 allow_url_include、disable_functions 等运行时设置对可利用性的影响。

未覆盖 / 证据缺口：
- 缺少 php.ini 与 Web 服务器配置，无法确认 shell_exec 是否被禁用
- 无端点清单，实际 URL 与访问控制未知
- 无部署/网络暴露面信息

## 3. Findings

### F-1: 025.php ping 功能通过 $_REQUEST['ip'] 造成命令注入（黑名单可绕过）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`025.php:5-30`
- **来源**：`llm_finding`

**描述**

脚本在 $_POST['Submit'] 存在时读取 $_REQUEST['ip']（第 5 行），仅用 str_replace 做黑名单替换（第 8-21 行），随后直接拼接进 shell_exec('ping -c 4 ' . $target)（第 30 行，Windows 分支为第 26 行）。黑名单只删除 ||、&、;、'| '、-、$、(、)、` 等子串，未删除换行符 \n、未删除单个 |、未删除 >、<、空格组合等，且 str_replace 是单次顺序替换，可用嵌套构造绕过（例如 '|' 后接被删字符重组）。攻击者可在 ip 参数中注入换行或管道符执行任意系统命令，获得服务器命令执行权限。

**source / sink**

- source：body `ip`（025.php:5）
- sink：025.php:30 shell_exec('ping  -c 4 ' . $target) 位于 025.php:30（Windows 分支 025.php:26）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `025.php:3` | 检测到 POST 参数 Submit 后进入处理分支 | 请求进入业务逻辑 |  |
| 2 | `025.php:5` | 从 $_REQUEST['ip'] 读取攻击者输入并 trim | $target = 攻击者可控字符串 |  |
| 3 | `025.php:8-21` | 用黑名单数组对 $target 做 str_replace 删除若干子串 | $target 被过滤，但换行符、单个 \|、>、< 等未被删除 | 黑名单不完整：未过滤 \n、单个 '\|'、'>'、'<'；且 str_replace 顺序替换可被嵌套构造绕过（如 '\|' + 被删字符重组） |
| 4 | `025.php:30` | 过滤后的 $target 直接拼接进 shell_exec 执行 ping 命令 | $target 作为 shell 命令的一部分被解释执行 | 无参数化、无 escapeshellarg，直接字符串拼接 |

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

远程未授权攻击者可在服务器上执行任意系统命令，完全控制 Web 服务器进程权限，读取敏感文件、横向移动、植入后门。

**CVE / CWE 论证**

CWE-78 OS 命令注入。外部可达（HTTP 参数 ip），无需认证，source→sink 链完整闭合，黑名单过滤可绕过，属于典型 CVE 级命令注入。

**修复建议**

不要将用户输入拼接进 shell 命令；使用 escapeshellarg() 对 $target 转义，或改用 filter_var($target, FILTER_VALIDATE_IP) 严格校验为合法 IP 后再拼接；避免使用 shell_exec，改用参数化方式调用。

**验证说明**

需动态确认目标 PHP 环境未禁用 shell_exec、php_uname 分支走向（*nix 用 -c 4），以及换行/管道在具体 shell 下的解释行为；黑名单绕过 payload 需按实际 shell 微调。
模型 POC 要点：向 025.php 提交 ip 参数，利用换行符或管道符在 ping 命令后追加任意命令，命令输出通过 $cmd 回显在 <pre> 中。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /025.php）：针对 025.php 的 OS 命令注入 POC（POST 通道）。注入点为 POST 表单参数 ip，其值被拼接进系统命令执行；payload 为 ;id，用于在命令后追加执行 id。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /025.php）：符合 CWE-78（OS 命令注入）。漏洞位于 025.php:30，外部输入来自 POST body 参数 ip，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。脚本中的 TARGET 需替换为授权测试实例地址后由测试人员手动执行；禁止用于未授权目标。

### F-2: 025.php Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`025.php:24-26`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入（025.php:5 读取该参数并赋给 `$target`）。程序在 025.php:24 用 `stristr(php_uname('s'), 'Windows NT')` 判断运行平台，命中 Windows 分支后，在 025.php:26 执行 `$cmd = shell_exec( 'ping  ' . $target );`。`$target` 未经任何转义、白名单校验或参数化，直接以字符串拼接方式进入 `shell_exec`，因此 `ip` 中的 shell 元字符（如 `&`、`|`、`;`、`&&`）会被命令解释器解析，从而在 Web 进程权限下执行任意命令。该分支的校验完全缺失，不存在可绕过的净化逻辑。

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

远程未认证攻击者可在目标主机上以 Web 服务进程权限执行任意系统命令，导致服务器完全失陷（读取/篡改文件、横向移动、植入后门）。Windows 分支下可通过 `&`、`|` 等分隔符追加命令。

**CVE / CWE 论证**

CWE-78（OS 命令注入）：外部可控的 `ip` 参数经 `$target` 直接拼接到 `shell_exec` 的命令字符串，无参数化或转义。该入口为公开 HTTP 查询参数，无需认证即可到达 025.php:26，利用链闭合（source 025.php:5 → sink 025.php:26）。

**修复建议**

不要用字符串拼接构造 shell 命令。使用 `escapeshellarg($target)` 对参数做转义，并配合 `escapeshellcmd`；更优做法是用白名单校验 `ip` 仅允许合法 IP/主机名（如 `filter_var($target, FILTER_VALIDATE_IP)` 或严格正则），校验失败直接拒绝；或改用不经过 shell 的 API（如 `proc_open` 传数组参数）并限制 ping 可执行文件路径与最小权限运行。

**验证说明**

静态证据：入口 ANY /025；source=query/ip；sink=025.php:26；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `025.php?ip=TARGET注入载荷` → 025.php:5 读取 `ip` 赋给 `$target` → 025.php:24 平台判断进入 Windows 分支 → 025.php:26 `shell_exec('ping  ' . $target)` 拼接执行 → 注入的命令被 shell 解释执行。
PocWriter 建议（未采纳，缺少端点 /025）：针对 025.php 的 OS 命令注入 POC（GET/query 通道）。注入点为查询参数 ip，其值被拼接进系统命令执行；payload 为 ;id。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /025）：符合 CWE-78（OS 命令注入）。漏洞位于 025.php:26，外部输入来自 query 参数 ip，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。TARGET 需替换为授权测试实例地址后由测试人员手动执行；禁止用于未授权目标。

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
| safety_guard | 安全防护 | 2.56 | 是 |
| surface_mapper | 攻击面测绘 | 9.02 | 是 |
| deep_finder | LLM 深挖 | 8.8 | 是 |
| candidate_screener | 候选筛选 | 4.06 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.32 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.51 | 是 |
| coordinator | 管线协调 | 4.96 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
