# 落日二号乙漏洞挖掘报告 — 20261031-172942-537011

- 生成时间：2026-10-31T09:30:27.503897+00:00
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

本次汇总仅含 1 个 PHP 源文件 027.php（30 行）的审计结果，共 2 条去重后 finding，全部为 command_injection（critical）：LLM-ee1cf990d74d 指出 ping 功能通过 ip 参数拼接命令、黑名单仅过滤 && 与 ;，GEN-2b40f95f1bb0 指出 Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）。两条均带 POC（HTTP 型，目标以 TARGET 占位，仅限授权测试），最高危即该命令注入，可直接导致服务器命令执行。POC 齐全度为 2/2，但均为静态源码推导的文本工件，未做动态验证。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 804 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 CODE PACK 中唯一文件 027.php（1-30 行）。该脚本从 $_REQUEST['ip'] 取参，仅用 str_replace 过滤 '&&' 与 ';'，随后直接拼接进 shell_exec 执行 ping，构成未认证命令注入（CWE-78），链路完整闭合。未发现 SQL 拼接、文件包含、反序列化、SSRF、弱哈希/弱随机、硬编码凭据或 Cookie 标志问题（脚本中无相关调用）。输入未提供部署配置（php.ini、disable_functions、Web 服务器配置）与端点清单，实际可利用性依赖 shell_exec 是否被禁用及脚本是否公网可达，需人工/动态确认。

未覆盖 / 证据缺口：
- 无 php.ini/disable_functions 配置，无法确认 shell_exec 是否可用
- 无部署信息，无法确认脚本公网可达性
- 无端点清单，endpoint 依据脚本自身推断为 /027.php

## 3. Findings

### F-1: 027.php ping 功能通过 ip 参数导致命令注入（黑名单仅过滤 && 与 ;）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`027.php:5-23`
- **来源**：`llm_finding`

**描述**

脚本在 $_POST['Submit'] 存在时，从 $_REQUEST['ip'] 读取用户输入（第 5 行），仅用 str_replace 删除 '&&' 与 ';' 两个子串（第 8-14 行），随后直接拼接进 shell_exec('ping -c 4 ' . $target)（*nix，第 23 行）或 shell_exec('ping ' . $target)（Windows，第 19 行）。黑名单未过滤管道符 '|'、后台执行 '&'、换行、反引号、$() 等，攻击者可在 ip 参数中注入任意命令并以 Web 服务器权限执行，形成完整 RCE。

**source / sink**

- source：body `ip`（027.php:5）
- sink：027.php:23 shell_exec('ping  -c 4 ' . $target)（第 23 行）/ shell_exec('ping ' . $target)（第 19 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `027.php:3` | 判断 POST 参数 Submit 是否存在，作为进入处理逻辑的开关 | 请求进入分支 |  |
| 2 | `027.php:5` | 从 $_REQUEST['ip'] 读取攻击者可控输入赋给 $target | $target = 攻击者原始字符串 |  |
| 3 | `027.php:8-14` | 黑名单仅删除 '&&' 与 ';' 两个子串，其余 shell 元字符（\|、&、换行、反引号、$()）原样保留 | $target 经不完整黑名单过滤，仍含可执行元字符 | 黑名单只覆盖 '&&' 和 ';'，未过滤 '\|'、单个 '&'、换行、反引号、$() 等，可用管道符或后台符绕过 |
| 4 | `027.php:17-23` | 按操作系统选择命令模板，将 $target 直接字符串拼接进 shell_exec | 拼接后的完整 shell 命令字符串 |  |
| 5 | `027.php:23` | shell_exec 执行拼接命令，命令注入生效 | 命令在服务器上执行，输出回显到 $cmd |  |

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

未认证远程攻击者可在 Web 服务器权限下执行任意系统命令，完全控制主机，读取敏感文件、横向移动。

**CVE / CWE 论证**

CWE-78 OS 命令注入。外部 HTTP 参数 ip 直达 shell_exec，黑名单不完整可绕过，无需认证，链路在 CODE PACK 内完全闭合。

**修复建议**

避免将用户输入拼接进 shell 命令；使用 escapeshellarg() 对 $target 转义，或改用白名单校验（仅允许合法 IP/主机名正则），并禁用不必要的 shell_exec。

**验证说明**

需动态确认 shell_exec 未被 disable_functions 禁用、Web 服务器可访问该脚本；命令注入本身由源码可直接判定。
模型 POC 要点：向 027.php 提交 Submit 与含管道符的 ip 值，绕过仅过滤 && 与 ; 的黑名单，在 ping 之后追加任意命令并回显结果
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /027.php）：针对 027.php（POST）的 OS 命令注入 POC。注入点为 POST 表单参数 ip（源码 027.php:23 处将 ip 拼入系统命令执行），payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /027.php）：符合 CWE-78（OS 命令注入）。漏洞位于 027.php:23，外部输入来自 POST body 参数 ip，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱；脚本中的 TARGET 需由授权测试人员手动替换。仅限授权测试。

### F-2: 027.php Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`027.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入（027.php:5 读取到 `$target`），该值未经任何转义或白名单校验，在 Windows 分支（`stristr(php_uname('s'),'Windows NT')` 为真，027.php:17）被直接字符串拼接到 `shell_exec('ping  ' . $target)`（027.php:19）。由于拼接发生在 shell 解释之前，`$target` 中的 `&`、`|`、`;`、`&&` 等 shell 元字符会被命令解释器当作命令分隔符执行，从而在 Web 服务器进程权限下执行任意系统命令。校验无效的原因：代码中不存在 escapeshellarg/escapeshellcmd、不存在 IP 格式白名单、不存在参数化调用（如 proc_open 数组形式），仅做平台判断后直接拼接。

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

远程未认证攻击者可在目标主机上以 Web 服务进程权限执行任意操作系统命令，导致服务器完全失陷（读取/篡改文件、横向移动、植入后门）。属于 RCE 级别影响。

**CVE / CWE 论证**

CWE-78（OS Command Injection）。外部可达性：入口为 HTTP query 参数 `ip`，无需认证即可访问 027.php；利用链闭合：source（027.php:5 的 `ip`）→ 变量 `$target` → 无净化 → sink（027.php:19 `shell_exec`），Windows 平台分支下必然触发。

**修复建议**

不要通过 shell 拼接执行 ping：改用参数数组形式（如 `proc_open(['ping', $target], ...)`）或 PHP 的 `filter_var($target, FILTER_VALIDATE_IP)` 严格校验并拒绝非 IP 输入；若必须调用 shell，使用 `escapeshellarg($target)` 并对 IP 做白名单/正则校验；同时以最小权限运行 Web 进程。

**验证说明**

静态证据：入口 POST /027；source=query/ip；sink=027.php:19；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `027.php?ip=TARGET` 并注入 shell 元字符（如 `127.0.0.1 & whoami`）→ 027.php:5 将参数写入 `$target` → 027.php:17 判定为 Windows NT → 027.php:19 执行 `shell_exec('ping  ' . $target)`，注入的命令被 shell 解释执行。
PocWriter 建议（未采纳，缺少端点 /027）：针对 027.php（POST）的 OS 命令注入 POC。注入点为 POST 表单参数 ip（源码 027.php:19 处将 ip 拼入系统命令执行），payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /027）：符合 CWE-78。漏洞位于 027.php:19，外部输入来自 POST body 参数 ip，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱；TARGET 需由授权测试人员手动替换。仅限授权测试。

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
| safety_guard | 安全防护 | 3.67 | 是 |
| surface_mapper | 攻击面测绘 | 7.64 | 是 |
| deep_finder | LLM 深挖 | 8.34 | 是 |
| candidate_screener | 候选筛选 | 3.68 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.75 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.39 | 是 |
| coordinator | 管线协调 | 5.99 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
