# 落日二号乙漏洞挖掘报告 — 20261031-002102-f84d0d

- 生成时间：2026-10-30T16:21:45.860270+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\026.zip`
- 输入模式：`zip`
- SHA256：`7273281abb4c6a51c2b466c5f7fb770cc8a05c6b22a7a39a27ade9248e1a1d28`
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

本次汇总基于单文件 PHP 脚本 026.php（21 行）的源码审计结果，共 2 条已去重 findings，均为 command_injection（critical）：LLM-709cbd914c63 指出 026.php 第 14 行附近通过 $_REQUEST['ip'] 拼接 shell_exec 形成未授权远程命令执行；GEN-a86a53dc898b 指出第 10 行附近 Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）。两条均带 POC（HTTP 型，可动态复现），POC 齐全度 2/2。最高危为 026.php 的未授权命令注入：脚本无认证/授权层、无框架中间件，参数读取与危险汇点紧邻，若对外暴露则可直接 RCE。需注意：两条 finding 分别落在第 10 行与第 14 行，属同一脚本内不同分支/汇点的独立证据，非重复计数。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 533 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 026.php（21 行，完整展示 1-21 行），已逐行审计。该脚本为典型 ping 命令注入示例：第 3 行以 POST Submit 作为入口，第 5 行从 $_REQUEST['ip'] 取原始输入，第 10/14 行直接拼接进 shell_exec，无任何过滤或认证，形成闭合的未授权命令注入链，已作为 critical 报告。未发现 SQL 注入、文件包含、SSRF、反序列化等其他汇点（文件内无相关函数）。未覆盖范围：无 composer.json/依赖、无 php.ini 与 Web 服务器配置、无路由清单，无法确认 disable_functions、open_basedir、实际 URL 路径与前置鉴权网关；这些仅影响可利用性细节，不改变注入链本身的成立。

未覆盖 / 证据缺口：
- 缺少 php.ini/Web 服务器配置，无法确认 shell_exec 是否被禁用及脚本实际暴露路径
- 无端点/路由清单，无法确认是否存在前置鉴权或 WAF
- 无依赖清单，无法评估第三方组件风险

## 3. Findings

### F-1: 026.php ping 功能通过 $_REQUEST['ip'] 拼接 shell_exec 导致未授权远程命令执行

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`026.php:5-14`
- **来源**：`llm_finding`

**描述**

026.php 在收到 POST 参数 Submit 后，直接从 $_REQUEST['ip'] 读取用户输入（第 5 行），未做任何白名单、转义或参数化处理，随后在第 10 行（Windows 分支）或第 14 行（*nix 分支）将其字符串拼接到 shell_exec('ping ... ' . $target) 中执行。攻击者可在 ip 参数中注入 shell 元字符（如 ; | & ` $() 换行）执行任意系统命令。由于 $_REQUEST 同时接受 GET/POST/Cookie，且脚本无任何认证或 CSRF 防护，任何能访问该脚本的人均可直接触发，形成未授权 RCE。

**source / sink**

- source：body `ip`（026.php:5）
- sink：026.php:14 shell_exec('ping -c 4 ' . $target) / shell_exec('ping  ' . $target)

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `026.php:3` | 判断 POST 参数 Submit 是否存在，作为进入处理逻辑的开关 | 攻击者控制 Submit=1 即可进入分支 |  |
| 2 | `026.php:5` | 从 $_REQUEST['ip'] 读取原始输入并赋给 $target，无任何过滤/转义 | 原始未过滤字符串，可含 shell 元字符 | 无白名单、无 escapeshellarg/escapeshellcmd、无正则校验 |
| 3 | `026.php:8` | 通过 php_uname('s') 判断操作系统，选择对应命令模板 | 仅决定拼接前缀，不影响污点内容 |  |
| 4 | `026.php:10` | Windows 分支将 $target 直接拼接到 ping 命令并交给 shell_exec 执行 | 污点字符串进入 shell 命令行 |  |
| 5 | `026.php:14` | *nix 分支将 $target 直接拼接到 'ping -c 4 ' 后交给 shell_exec 执行，命令注入在此触发 | 污点字符串进入 shell 命令行，元字符被 shell 解释执行 |  |

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
- POC 目录：`poc/LLM-709cbd914c63`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

未授权攻击者可在服务器上以 Web 服务进程权限执行任意系统命令，读取敏感文件、横向移动、植入后门，完全控制主机。

**CVE / CWE 论证**

CWE-78 OS 命令注入。外部可达（无认证、无 CSRF token），source（$_REQUEST['ip']）到 sink（shell_exec）链路完整且无任何过滤，属于典型 DVWA 式命令注入，可稳定复现，符合 CVE/赏金平台接收标准。

**修复建议**

不要将用户输入拼接进 shell 命令；使用 escapeshellarg() 对 $target 转义，或改用白名单校验 IP 格式（filter_var($target, FILTER_VALIDATE_IP)），并优先使用参数化方式（如 proc_open 传数组参数）执行 ping。

**验证说明**

需在目标环境确认 shell_exec 未被 disable_functions 禁用、脚本实际 URL 路径与是否对外暴露；动态验证时观察 <pre> 回显即可确认。
模型 POC 要点：向 026.php 提交 Submit 与含命令分隔符的 ip 参数，使 shell_exec 在 ping 命令后追加执行任意命令，并将输出回显到页面 <pre> 中。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /026.php）：针对 026.php（POST 入口）的 OS 命令注入 POC。注入点为 POST 请求体参数 ip，payload 为 ;id，目标地址统一使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /026.php）：符合 CWE-78（OS 命令注入）。漏洞位于可交付代码 026.php:14，外部输入来自 POST body 参数 ip，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。脚本中的 TARGET 需由授权测试人员手动替换；执行前须确认授权范围。request.http 中 Content-Length 为 8，对应 ip=%3Bid 的字节长度。

### F-2: 026.php Windows 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`026.php:8-10`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `ip` 提供输入，该参数在 026.php:5 被读入变量 `target`，随后在 026.php:8 通过 `stristr(php_uname('s'), 'Windows NT')` 判断运行平台；当目标为 Windows 时进入 026.php:10，执行 `$cmd = shell_exec( 'ping  ' . $target );`。代码仅做字符串拼接，未对 `target` 做任何白名单校验、转义（如 escapeshellarg）或参数化，因此 `target` 中的 shell 元字符（如 `&`、`|`、`;`）会被 shell 解释为命令分隔符，导致任意命令执行。该分支的触发条件为服务器运行于 Windows NT 平台。

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

远程未认证攻击者可在 Web 服务器进程权限下执行任意操作系统命令，导致服务器完全失陷、敏感数据泄露、横向移动及持久化。

**CVE / CWE 论证**

CWE-78（OS 命令注入）。外部可达性：注入点为 HTTP 查询参数 `ip`，无需认证即可访问；利用链闭合：`ip` → `target`（026.php:5）→ 字符串拼接进入 `shell_exec`（026.php:10），中间无有效净化。该分支仅在 Windows 平台生效，属平台条件性可达。

**修复建议**

避免将外部输入拼接进 shell 命令；改用参数数组形式调用（如 proc_open/exec 传入参数数组），或对 `target` 使用严格白名单（仅允许合法 IP/主机名正则），并在必须拼接时使用 escapeshellarg/escapeshellcmd 转义；同时以最小权限运行 Web 进程。

**验证说明**

静态证据：入口 ANY /026；source=query/ip；sink=026.php:10；规则 php-exec。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `026.php?ip=TARGET` 并注入 shell 元字符 → 026.php:5 读入 `target` → 026.php:8 判定为 Windows NT → 026.php:10 `shell_exec('ping  ' . $target)` 执行拼接后的命令 → 任意命令执行。
PocWriter 建议（未采纳，缺少端点 /026）：针对 026（ANY 方法入口）的 OS 命令注入 POC。注入点为查询字符串参数 ip，payload 为 ;id，目标地址统一使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /026）：符合 CWE-78（OS 命令注入）。漏洞位于可交付代码 026.php:10，外部输入来自 query 参数 ip，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。脚本中的 TARGET 需由授权测试人员手动替换；执行前须确认授权范围。ANY 为占位方法，实际测试可替换为 GET 或 POST，但注入通道仍为查询参数 ip。

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
| safety_guard | 安全防护 | 2.4 | 是 |
| surface_mapper | 攻击面测绘 | 8.1 | 是 |
| deep_finder | LLM 深挖 | 9.12 | 是 |
| candidate_screener | 候选筛选 | 3.07 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.48 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.66 | 是 |
| coordinator | 管线协调 | 5.8 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
