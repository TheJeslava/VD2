# 落日二号乙漏洞挖掘报告 — 20261031-014053-3ceea6

- 生成时间：2026-10-30T17:41:35.278229+00:00
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

本次审计范围仅覆盖单个 PHP 文件 026.php（21 行），共交付 2 条 command_injection 发现（LLM-2a458faae535 与 GEN-a86a53dc898b），严重度均为 critical，且两条均附带 POC 文本（静态 POC，未执行、未做动态验证）。最高危项是 026.php 中通过 $_REQUEST['ip'] 拼接进 ping 命令并交由 shell_exec 执行，属于典型的参数直通汇点（source 与 sink 高度耦合），攻击者可在无需认证线索的前提下实现任意命令执行。POC 齐全度：2/2 有 POC，但均为文本工件，未在沙箱或真实环境验证，不能宣称可动态复现。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 533 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 026.php（21 行）。已审计其全部代码：入口为 POST Submit 触发的 $_REQUEST['ip'] 读取（第 5 行），sink 为第 10/14 行的 shell_exec 命令拼接，构成完整且无过滤的命令注入链，已作为 critical 报告。未发现 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 等配置型问题（文件中无相关调用）。未覆盖范围：无路由/部署/php.ini 信息，无法确认 disable_functions、open_basedir 及是否被 include 复用；无其它文件可审计。输入中未出现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- 缺少 php.ini（disable_functions、open_basedir）无法评估命令执行边界
- 缺少部署与路由信息，无法确认 026.php 是否直接对外暴露或存在前置认证
- 无其它文件/依赖清单，供应链风险未评估

## 3. Findings

### F-1: 026.php ping 功能通过 $_REQUEST['ip'] 造成命令注入（shell_exec）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`026.php:3-15`
- **来源**：`llm_finding`

**描述**

026.php 在收到 POST 参数 Submit 后，直接把 $_REQUEST['ip'] 拼接到 shell_exec('ping -c 4 ' . $target)（Windows 分支为 shell_exec('ping  ' . $target)）中执行，未做任何转义、白名单或参数化。攻击者可在 ip 参数中注入 shell 元字符（;、|、&&、$()、反引号），在服务器上执行任意系统命令，导致远程代码执行。

**source / sink**

- source：body `ip`（026.php:5）
- sink：026.php:15 shell_exec('ping  -c 4 ' . $target) / shell_exec('ping  ' . $target)

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `026.php:3` | 检查 POST 参数 Submit 是否存在，作为进入处理逻辑的开关 | 攻击者提交 Submit=Submit 即可满足条件 |  |
| 2 | `026.php:5` | 从 $_REQUEST['ip'] 读取攻击者完全可控的输入，未做任何过滤 | 原始字符串，未过滤/未转义 | 无任何输入校验 |
| 3 | `026.php:8` | 通过 php_uname('s') 判断操作系统，选择对应分支 | 仅影响拼接前缀，不影响污点数据 |  |
| 4 | `026.php:14` | 将污点变量 $target 直接字符串拼接到 ping 命令后交给 shell_exec 执行（*nix 分支） | 污点数据进入 shell 命令字符串 | 无 escapeshellarg/escapeshellcmd，无白名单 |
| 5 | `026.php:10` | Windows 分支同样将 $target 直接拼接进 shell_exec | 污点数据进入 shell 命令字符串 |  |

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
  --data 'ip=%3Bid'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/LLM-2a458faae535`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

未认证远程攻击者可在 Web 服务器进程权限下执行任意系统命令，完全控制服务器，读取敏感文件、横向移动。

**CVE / CWE 论证**

CWE-78 OS 命令注入。source（$_REQUEST['ip']）到 sink（shell_exec）链路完整闭合，无任何过滤，外部无需认证即可触发，属典型 CVE 级 RCE。

**修复建议**

不要将用户输入拼接进 shell 命令；使用 escapeshellarg() 包裹参数，或改用白名单校验 IP 格式（filter_var($target, FILTER_VALIDATE_IP)），并避免使用 shell_exec。

**验证说明**

需动态确认 026.php 对外可达、shell_exec 未被 disable_functions 禁用；payload 需按目标操作系统调整。
模型 POC 要点：向 026.php 提交 ip 参数，利用分号/管道注入额外命令，命令输出通过 $cmd 回显在 <pre> 中
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /026.php）：针对 026.php（POST 入口）的 OS 命令注入 POC。注入点为 POST 请求体参数 ip，该参数被拼接进系统命令执行（CWE-78），payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /026.php）：符合 CWE-78（OS 命令注入）。漏洞位于可交付代码 026.php:15，外部输入来自 POST body 参数 ip，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权测试目标，并确保已获书面授权。request.http 中 Content-Length 按实际 body 长度调整。

### F-2: 026.php Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`026.php:8-10`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入（026.php:5 读取该参数并赋给 `$target`）。当 `php_uname('s')` 返回包含 `Windows NT` 的字符串时（026.php:8 的 `stristr` 判断成立），代码进入 Windows 分支，在 026.php:10 执行 `$cmd = shell_exec( 'ping  ' . $target );`。`$target` 未经任何转义、白名单校验或参数化处理，直接以字符串拼接方式进入 `shell_exec`，因此 `&`、`|`、`&&`、`||` 等 Windows shell 元字符可截断 ping 命令并追加任意命令。该分支仅在 Windows 主机上触发，属于平台相关的利用条件，但一旦满足即无需认证即可远程执行命令。

**source / sink**

- source：query `ip`（026.php:5）
- sink：026.php:10 $cmd = shell_exec( 'ping  ' . $target );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `026.php:5` | 从 query `ip` 读取外部输入 | 污点进入 target |  |
| 2 | `026.php:10` | 危险汇点：$cmd = shell_exec( 'ping  ' . $target ); | 污点进入 command_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /026（ANY）的 OS 命令注入 POC。注入点：ANY 参数 ip；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/026'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 OS 命令注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/026?ip=%3Bid'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`;id`
- POC 目录：`poc/GEN-a86a53dc898b`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

远程未认证攻击者可在 Windows 部署的服务器上以 Web 服务进程权限执行任意系统命令，导致服务器完全失陷、敏感数据泄露、内网横向移动及持久化。

**CVE / CWE 论证**

CWE-78（OS 命令注入）：外部可控的查询参数 `ip` 经 `$target` 直接拼接进 `shell_exec` 的命令字符串，无转义、无白名单、无参数化，利用链闭合。可达性：HTTP GET 查询参数即可触达，无需认证；触发条件为运行环境为 Windows（`php_uname('s')` 含 `Windows NT`），属环境前置条件而非访问控制限制。

**修复建议**

不要通过 shell 拼接执行 ping：使用 `escapeshellarg($target)` 对参数做严格转义，或改用 `proc_open` 以参数数组形式传参（避免 shell 解析）；同时对 `$target` 做严格白名单校验（如 `filter_var($target, FILTER_VALIDATE_IP)` 或仅允许 `[A-Za-z0-9.-]`），并限制 ping 的目标与超时；以最小权限账户运行 Web 服务。

**验证说明**

静态证据：入口 ANY /026；source=query/ip；sink=026.php:10；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：026.php:5 从查询参数 `ip` 读取 `$target` → 026.php:8 `stristr(php_uname('s'),'Windows NT')` 为真进入 Windows 分支 → 026.php:10 `shell_exec('ping  ' . $target)` 将未净化输入拼入 shell 命令 → 注入的 shell 元字符执行任意命令。
PocWriter 建议（未采纳，缺少端点 /026）：针对 026.php（ANY 方法入口）的 OS 命令注入 POC。注入点为查询字符串参数 ip，该参数被拼接进系统命令执行（CWE-78），payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /026）：符合 CWE-78（OS 命令注入）。漏洞位于可交付代码 026.php:10，外部输入来自 query 参数 ip，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权测试目标，并确保已获书面授权。ANY 方法在文本中以 GET 示例呈现，实际可按目标路由支持的方法调整。

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
| safety_guard | 安全防护 | 2.51 | 是 |
| surface_mapper | 攻击面测绘 | 7.97 | 是 |
| deep_finder | LLM 深挖 | 6.98 | 是 |
| candidate_screener | 候选筛选 | 4.0 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.39 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.53 | 是 |
| coordinator | 管线协调 | 5.68 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
