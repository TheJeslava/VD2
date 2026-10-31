# 落日二号乙漏洞挖掘报告 — 20261031-214529-45ce27

- 生成时间：2026-10-31T13:46:23.100546+00:00
- 输入：`$WORKSPACE\暴风星云裂\027.zip`
- 输入模式：`zip`
- SHA256：`0692e8f3bcf09553285200fdbb5eecd31f5db885c7d44a68982905afded500d3`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.5.0-ver5
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总基于单文件 PHP 脚本 027.php 的已去重 findings：共 2 条 command_injection（均为 critical），分别来自 LLM 审计（LLM-ee1cf990d74d，第 23 行 shell_exec 拼接 $_REQUEST['ip']）与规则引擎（GEN-2b40f95f1bb0，第 19 行 Windows 分支 ping 命令拼接），两条均带 POC，属 HTTP 型可复现文本工件（未执行、未动态验证）。最高危即该命令注入：请求参数直连 shell_exec，无 escapeshellarg/escapeshellcmd 中间层，若脚本公开可达则可直接执行任意系统命令。POC 齐全度：2/2 有 POC，但均为静态构造文本，未做动态确认。二次注入链：本次无。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 804 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：CODE PACK 仅含单文件 027.php（30 行）。已审计其唯一入口：$_POST['Submit'] 触发、$_REQUEST['ip'] 读取，经不完整黑名单（仅删 '&&' 与 ';'）后拼接进 shell_exec 执行 ping，构成闭合的命令注入链（CWE-78），可外部未认证触发。未发现 SQL/文件包含/反序列化/SSRF 等其他汇点；无 session/认证代码，无法判断访问控制。weak_hash/weak_crypto/weak_random/insecure_cookie/hardcoded_secret 等配置型线索在代码中均无对应实现，不成立。

未覆盖 / 证据缺口：
- 无 php.ini/部署信息，无法确认 shell_exec 是否被禁用
- 无认证/网关信息，无法确认脚本暴露面
- 无其他文件，第三方依赖与配置型风险无法评估

## 3. Findings

### F-1: 027.php ping 功能通过 $_REQUEST['ip'] 拼接 shell_exec 导致命令注入

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.93`
- **结论**：`candidate` / 证据等级 `externally_corroborated`
- **位置**：`027.php:5-23`
- **来源**：`llm_finding`

**描述**

脚本在 $_POST['Submit'] 存在时，从 $_REQUEST['ip'] 读取用户输入（第 5 行），仅用黑名单 str_replace 删除 '&&' 与 ';'（第 8-14 行），随后直接拼接进 shell_exec('ping -c 4 ' . $target)（第 23 行，Windows 分支为第 19 行）。黑名单不覆盖管道符 |、反引号 `、$()、换行符、& 单字符、|| 等，攻击者可在 ip 参数中注入任意命令并以 Web 进程权限执行，构成远程命令执行。

**source / sink**

- source：body `ip`（027.php:5）
- sink：027.php:23 shell_exec('ping  -c 4 ' . $target)（第 23 行）/ shell_exec('ping  ' . $target)（第 19 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `027.php:3` | 检查 $_POST['Submit'] 是否存在，作为进入处理逻辑的开关 | 请求体包含 Submit 字段即通过 |  |
| 2 | `027.php:5` | 从 $_REQUEST['ip'] 读取攻击者可控输入赋给 $target | 原始用户字符串，未过滤 |  |
| 3 | `027.php:8-14` | 黑名单仅删除 '&&' 与 ';' 两个子串 | 其余 shell 元字符（\|、`、$()、&、换行）原样保留 | 黑名单不完整，未覆盖管道符、命令替换、单 & 等，且未使用 escapeshellarg |
| 4 | `027.php:23` | 将 $target 直接拼接进 shell_exec 执行 ping 命令 | 拼接后的 shell 命令字符串进入 shell_exec |  |

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

未认证攻击者可在服务器上以 Web 进程权限执行任意系统命令，完全控制主机，读取敏感文件、横向移动。

**CVE / CWE 论证**

CWE-78 OS 命令注入。source（$_REQUEST['ip']）到 sink（shell_exec）链路在 CODE PACK 内完整闭合，黑名单可被 '|' 等字符绕过，无需认证即可外部触发。

**修复建议**

不要将用户输入拼接进 shell 命令；使用 escapeshellarg($target) 转义，或改用白名单校验 IP 格式（filter_var($target, FILTER_VALIDATE_IP)），并避免使用 shell_exec 执行外部命令。

**验证说明**

需动态确认目标 OS 分支与 shell_exec 是否被 disable_functions 禁用；POC 仅限授权测试。
模型 POC 要点：在 ip 参数中注入管道符执行任意命令，黑名单不拦截 '|'
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
AWVS 外部佐证：OS Command Injection @ http://127.0.0.1:18081/027.php（未在本管线执行扫描）。
PocWriter 建议（未采纳，缺少端点 /027.php）：针对 027.php 第 23 行的 OS 命令注入 POC。注入点为 POST 请求体参数 ip，该参数被拼接进系统命令执行函数（CWE-78）。payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /027.php）：符合 CWE-78（OS 命令注入）。漏洞位于 027.php:23，外部输入来自 POST body 参数 ip，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。执行前将 TARGET 替换为授权测试目标；仅限授权测试。请求结构沿用已有确定性 POC，未改动目标占位符。

**外部佐证**

- awvs: OS Command Injection @ http://127.0.0.1:18081/027.php

### F-2: 027.php Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`027.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入，该输入在 027.php:5 被读入变量 `target`（证据中 source 标注为 query `ip`）。程序在 027.php:17 用 `stristr(php_uname('s'), 'Windows NT')` 判断运行平台，命中 Windows 分支后，在 027.php:19 将 `target` 直接字符串拼接到 `shell_exec('ping  ' . $target)` 中执行。代码片段显示拼接前没有任何转义、白名单或参数化处理（无 escapeshellarg/escapeshellcmd、无 IP 格式校验），因此 `target` 中的 shell 元字符（如 `&`、`|`、`;`）会被命令解释器当作命令分隔符执行，校验完全失效。

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

远程未认证攻击者可在 Web 服务器进程权限下执行任意系统命令，导致服务器被完全控制（RCE）、敏感文件读取、内网横向移动与持久化。Windows 分支下可通过 `&`、`|` 等分隔符追加任意命令。

**CVE / CWE 论证**

CWE-78（OS 命令注入）：外部可控输入 `ip` 未经净化直接进入 `shell_exec` 命令字符串，利用链闭合（source 027.php:5 → sink 027.php:19），通过普通 HTTP GET 即可触达，无需认证。该分支仅在 `php_uname('s')` 含 'Windows NT' 时执行，属环境相关可达性，不影响漏洞成立。

**修复建议**

不要用 shell 拼接执行 ping：改用参数数组形式（如 `proc_open`/`exec` 传数组）或 PHP 原生 socket 实现连通性检测；若必须调用外部程序，对 `target` 做严格白名单校验（仅允许合法 IPv4/IPv6/域名正则），并使用 `escapeshellarg()` 包裹参数，同时以最小权限账户运行 Web 服务。

**验证说明**

静态证据：入口 POST /027；source=query/ip；sink=027.php:19；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET 请求携带参数 `ip=<payload>` → 027.php:5 读入 `target` → 027.php:17 判定为 Windows → 027.php:19 `shell_exec('ping  ' . $target)` 拼接执行 → 注入的命令在服务器上执行。
PocWriter 建议（未采纳，缺少端点 /027）：针对 027.php 第 19 行的 OS 命令注入 POC。注入点为参数 ip，被拼接进系统命令执行函数（CWE-78）。payload 使用 TARGET 占位符，仅限授权测试。注意：源码中 ip 的取值方式（query 或 body）需以 027.php:19 实际代码为准，若为 $_POST 则须使用 POST 请求体。
PocWriter 建议（未采纳，缺少端点 /027）：符合 CWE-78。漏洞位于 027.php:19，外部输入来自参数 ip，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。ip 的取值方式（query/body）需以 027.php:19 源码为准，若为 $_GET 请将载荷移至 URL 查询串。仅限授权测试，TARGET 为占位符。

## 4. 二次注入（SecondOrderAnalyzer）

本次未发现 store→read→sink 闭环的二次注入链。

## 5. AWVS 联动

- 输入模式：`zip`
- 导入结果：1 条
- 关联明细：1 条
- 目标种子：`awvs/targets.json`
- 说明：AWVS 是外部动态扫描器；本管线只导入其结果做佐证，或导出端点供 AWVS 播种。

| finding | AWVS | URL | 结论 |
|---|---|---|---|
| `LLM-ee1cf990d74d` | OS Command Injection | http://127.0.0.1:18081/027.php | corroborated |

## 6. 漏洞类型覆盖

| 类型 | CWE | AutoCVE | 本次数量 |
|---|---|---|---|
| `command_injection` | CWE-78 | 是 | 2 |
| `sql_injection` | CWE-89 | 是 | 0 |
| `blind_sql_injection` | CWE-89 |  | 0 |
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
| safety_guard | 安全防护 | 4.78 | 是 |
| surface_mapper | 攻击面测绘 | 10.59 | 是 |
| deep_finder | LLM 深挖 | 8.03 | 是 |
| candidate_screener | 候选筛选 | 5.2 | 是 |
| vulnerability_analyzer | 漏洞分析 | 8.17 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 10.19 | 是 |
| coordinator | 管线协调 | 6.66 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
