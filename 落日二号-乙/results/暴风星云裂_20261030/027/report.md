# 落日二号乙漏洞挖掘报告 — 20261030-224831-4c0e4f

- 生成时间：2026-10-30T14:49:06.701024+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\027.zip`
- 输入模式：`zip`
- SHA256：`0692e8f3bcf09553285200fdbb5eecd31f5db885c7d44a68982905afded500d3`
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

本次汇总仅含 1 条已去重 finding：027.php 中 ping 功能的 $_REQUEST['ip'] 经黑名单过滤后可绕过，最终进入 shell_exec，构成命令注入（critical，LLM-c9f36281b7cf），且已附带 POC 文本（静态构造，未执行、未动态验证）。最高危即该条命令注入，属单文件 PHP 脚本中请求参数到危险汇点的直连路径。POC 齐全度为 1/1，但仅为文本工件，需在授权环境自行验证。其余攻击面（文件包含/路径穿越、反射型 XSS、配置类弱实现）在 surface_notes 中列为待确认，未形成 finding，已转入人工复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 804 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中提供的单文件 027.php（30 行，已完整展示 1-30 行）。该脚本为 ping 演示工具：第3行以 POST 参数 Submit 作为入口开关，第5行通过 $_REQUEST['ip'] 读取外部输入，第8-14行仅用 str_replace 删除 '&&' 与 ';' 构成弱黑名单，第17-24行按操作系统拼接命令并调用 shell_exec，第27行回显输出。已确认一条闭合的命令注入链（CWE-78），黑名单可被管道符、命令替换、反引号、换行等绕过，无需认证即可 RCE。其余待确认面（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary/hardcoded_secret）在已展示的 30 行源码中均无对应实现（无 md5/sha1、无加密调用、无随机数生成、无 setcookie、无硬编码凭据、无 X-Forwarded-* 信任），故不单独立项。未覆盖范围：仓库其他文件、php.ini/.htaccess/Web 服务器配置、部署方式与运行用户、依赖清单均不在 code_pack 内，视为不存在；因此无法评估 allow_url_include、open_basedir、disable_functions 等开关对可利用性的影响。

未覆盖 / 证据缺口：
- 无 php.ini/.htaccess/Web 服务器配置，无法确认 disable_functions 是否禁用 shell_exec、open_basedir 限制
- 无部署方式与运行用户信息，无法精确评估命令执行影响面
- 无端点清单，无法确认该脚本是否位于认证之后或对外暴露
- 无依赖清单与版本历史，无法评估第三方组件 CVE 或该文件是否为调试残留

## 3. Findings

### F-1: 027.php ping 功能 $_REQUEST['ip'] 黑名单过滤可绕过导致 shell_exec 命令注入

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`027.php:3-27`
- **来源**：`llm_finding`

**描述**

027.php 在收到 POST 参数 Submit 后，从 $_REQUEST['ip'] 读取目标地址（第5行），仅用 str_replace 删除 '&&' 与 ';' 两个子串（第8-14行）作为黑名单，随后直接拼接进 shell_exec('ping -c 4 ' . $target)（第23行，Windows 分支为第19行）。黑名单只覆盖两个分隔符，未过滤管道符 |、命令替换 $()、反引号 ``、换行符、& 单符号、|| 等，攻击者可在 ip 参数中注入任意命令并以 Web 进程权限执行，构成完整的远程命令执行链。

**source / sink**

- source：body `ip`（027.php:5）
- sink：027.php:27 shell_exec( 'ping  -c 4 ' . $target )（第23行）；Windows 分支 shell_exec( 'ping  ' . $target )（第19行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `027.php:3` | 检查 POST 参数 Submit 是否存在，作为进入处理逻辑的开关 | 攻击者控制请求体，Submit 置任意值即可进入分支 |  |
| 2 | `027.php:5` | 从 $_REQUEST['ip'] 读取外部输入并赋给 $target | $target = 攻击者原始字符串（未过滤） |  |
| 3 | `027.php:8-14` | 用 str_replace 删除 '&&' 与 ';' 两个子串 | $target 仅去掉 '&&' 和 ';'，其余元字符（\|、$()、反引号、换行、单个 &、\|\|）原样保留 | 黑名单只覆盖两个分隔符，未过滤管道符 \|、命令替换 $()、反引号、换行符、单个 & 与 \|\|，可用这些构造命令分隔 |
| 4 | `027.php:17-24` | 按操作系统选择 ping 命令模板，将 $target 直接字符串拼接后交给 shell_exec | $target 未做任何转义（无 escapeshellarg/escapeshellcmd）即进入 shell 解释器 |  |
| 5 | `027.php:23` | shell_exec 执行拼接后的命令，返回输出写入 $cmd | 注入的命令在 shell 中执行，输出被捕获 |  |
| 6 | `027.php:27` | 将命令输出拼入 $html 并回显到页面 | 命令执行结果以 <pre> 形式返回给攻击者 |  |

**POC**

针对 /027.php（POST）的 OS 命令注入 POC。注入点为 POST 参数 ip，该参数被拼接进系统命令执行；payload 使用 TARGET 占位符，仅限授权测试。

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
- POC 目录：`poc/LLM-c9f36281b7cf`
- 执行状态：未执行（`executed=False`）

**影响**

未认证攻击者可在 Web 服务器上以 Web 进程权限执行任意系统命令，读取/篡改文件、横向移动、建立持久化，导致服务器完全失陷。

**CVE / CWE 论证**

CWE-78（OS 命令注入）。外部可达：$_REQUEST['ip'] 直接来自 HTTP 请求；无需认证；黑名单仅过滤 '&&' 与 ';'，管道符/命令替换/反引号/换行均可绕过；source→sink 链在 027.php 内完整闭合，无中间校验层。

**修复建议**

不要将用户输入拼接进 shell 命令。使用 escapeshellarg($target) 对参数转义，或改用白名单校验（如 filter_var($target, FILTER_VALIDATE_IP) 仅允许合法 IP），并避免使用 shell_exec 执行外部命令。

**验证说明**

需在授权环境确认 027.php 实际部署路径与运行用户；确认目标操作系统以选择第19行或第23行分支；确认 disable_functions 未禁用 shell_exec。POC 仅限授权测试。
模型 POC 要点：向 027.php 提交 ip 参数，利用未被黑名单覆盖的管道符或命令替换注入任意命令，并通过页面回显读取执行结果。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /027.php）：符合 CWE-78（OS 命令注入）。漏洞位于可交付代码 027.php:27，外部输入来自 POST body 参数 ip，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。目标地址统一使用 TARGET 占位符，仅限授权测试。请求结构沿用已有确定性 POC（POST /027.php，body ip=%3Bid），未改动文件与行号。如需验证可替换 payload 为无害命令（如 id、whoami），禁止使用破坏性命令。

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
| `command_injection` | CWE-78 | 是 | 1 |
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
| safety_guard | 安全防护 | 3.45 | 是 |
| surface_mapper | 攻击面测绘 | 9.88 | 是 |
| deep_finder | LLM 深挖 | 10.56 | 是 |
| candidate_screener | 候选筛选 | 1.97 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 3.82 | 是 |
| coordinator | 管线协调 | 5.97 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
