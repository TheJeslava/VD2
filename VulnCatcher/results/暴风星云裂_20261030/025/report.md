# 落日二号乙漏洞挖掘报告 — 20261030-224813-21746c

- 生成时间：2026-10-30T14:48:47.677059+00:00
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

本次汇总仅含 1 条已去重 finding：025.php 中 ping 功能将 $_REQUEST['ip'] 拼接进 shell_exec，构成命令注入（critical，LLM-229f7d2e8603），且已附带 POC（HTTP 型，可动态复现，仅限授权测试）。最高危即此条，属直接 RCE 面。POC 齐全度为 1/1（with_poc=1）。需注意：surface_notes 明确指出输入未提供 025.php 实际源码行与行号范围，攻击面测绘停留在文件级，因此该 finding 的行号与黑名单绕过细节应以代码复核为准，本次未做任何动态验证。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 950 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 025.php（37 行），已完整审计。该文件是一个 ping 工具页面：第 3 行检测 POST Submit，第 5 行从 $_REQUEST['ip'] 取输入，第 8-21 行用不完整黑名单做 str_replace，第 26/30 行将结果拼接进 shell_exec 执行。黑名单只删除 '\| '（竖线+空格）而不删除单独 '\|'，也不处理换行符，构成可绕过的命令注入，链完整闭合，已作为 critical 报告。其余攻击面：第 34 行 $html .= "<pre>{$cmd}</pre>" 输出的是命令执行结果而非用户输入，不构成 XSS；未发现 SQL、文件操作、动态 include、eval、弱加密/弱随机/不安全 Cookie 等其它汇点。未覆盖范围：无部署配置（php.ini、disable_functions）、无认证机制信息，无法确认运行时是否禁用 shell_exec；这些不影响静态链闭合，但影响实际可利用性。

未覆盖 / 证据缺口：
- 缺少 php.ini / disable_functions 配置，无法确认 shell_exec 是否被禁用
- 缺少 Web 服务器与 PHP 版本信息，无法确认操作系统分支与回显行为
- 无认证/会话文件，insecure_cookie、trust_boundary 类无法评估
- 无依赖清单，无法评估第三方组件 CVE

## 3. Findings

### F-1: 025.php ping 功能通过 $_REQUEST['ip'] 拼接 shell_exec 导致命令注入（黑名单可绕过）

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`025.php:5-30`
- **来源**：`llm_finding`

**描述**

025.php 在收到 POST 参数 Submit 后，从 $_REQUEST['ip'] 读取用户输入（第 5 行），仅用 str_replace 对黑名单字符（||、&、;、'| '、-、$、(、)、`）做删除（第 8-21 行），随后把结果直接拼接到 shell_exec('ping -c 4 ' . $target)（*nix，第 30 行）或 shell_exec('ping  ' . $target)（Windows，第 26 行）执行。黑名单存在多处缺陷：只删除 '| '（竖线加空格）而不删除单独的 '|'，因此可用 '|' 直接管道到任意命令；只删除 '||' 与 '&'，未处理换行符 %0a；删除 '-' 会破坏 ping 参数但不影响注入；删除 '$'、'('、')'、'`' 只阻断部分子 shell 语法。攻击者可用 '127.0.0.1|id' 或 '127.0.0.1
id' 绕过黑名单，实现任意命令执行，完全控制 Web 服务器进程权限。

**source / sink**

- source：body `ip`（025.php:5）
- sink：025.php:30 shell_exec('ping -c 4 ' . $target)（第 30 行，*nix）/ shell_exec('ping  ' . $target)（第 26 行，Windows）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `025.php:3` | 检测到 POST 参数 Submit 存在，进入命令执行分支 | 请求进入处理逻辑 |  |
| 2 | `025.php:5` | 从 $_REQUEST['ip'] 读取攻击者可控输入并 trim | 原始攻击者字符串，如 127.0.0.1\|id |  |
| 3 | `025.php:8-21` | 用黑名单数组对输入做 str_replace 删除；黑名单只含 '\| '（竖线+空格），不含单独 '\|'，也不含换行符 | '127.0.0.1\|id' 不含 '\| '（无空格），不被替换，原样保留 | 黑名单仅删除 '\| '（竖线后跟空格），攻击者使用 '\|' 紧跟命令（无空格）即可绕过；换行符 %0a 亦不在黑名单中 |
| 4 | `025.php:24-30` | 判断操作系统后把 $target 拼接到 ping 命令并交给 shell_exec 执行 | 最终命令字符串 'ping -c 4 127.0.0.1\|id'，由 shell 解释执行 | 拼接未使用 escapeshellarg/escapeshellcmd，shell 元字符 '\|' 生效 |

**POC**

针对 /025.php（POST）的 OS 命令注入 POC。注入点为 POST 参数 ip，源码 025.php:30 将该参数拼入系统命令执行；payload 使用 TARGET 占位符，仅限授权测试。

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
- 执行状态：未执行（`executed=False`）

**影响**

攻击者无需认证即可在 Web 服务器上以 Web 进程权限执行任意系统命令，可读取敏感文件、横向移动、植入后门，导致服务器完全失陷。

**CVE / CWE 论证**

CWE-78 OS 命令注入。外部可达（HTTP POST 参数 ip），无需认证，source→sink 链完整闭合：$_REQUEST['ip'] → str_replace 黑名单（可绕过）→ shell_exec 拼接执行。黑名单未覆盖单独 '|' 与换行符，绕过确定。

**修复建议**

不要拼接 shell 命令；使用 escapeshellarg($target) 对参数转义，或改用白名单校验 IP 格式（filter_var($target, FILTER_VALIDATE_IP)），并避免使用 shell_exec 调用外部 ping，改用 PHP 原生网络函数。

**验证说明**

需在目标环境确认 shell_exec 未被 disable_functions 禁用、Web 用户可执行 ping/id；确认操作系统分支以选择对应 payload。黑名单绕过基于源码静态分析，建议动态复现确认回显。
模型 POC 要点：向 025.php 提交 Submit 与 ip 参数，ip 中使用未被黑名单覆盖的 '|' 管道符注入任意命令，命令输出随 ping 结果回显在 <pre> 中
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /025.php）：符合 CWE-78（OS 命令注入）。漏洞位于可交付代码 025.php:30，外部输入来自 POST body 参数 ip，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权目标并确认书面授权。原始确定性请求结构（POST /025.php，body ip=%3Bid）保持不变，仅补充说明与预期结果。建议先用无副作用命令（如 id）验证，避免使用破坏性命令。

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
| safety_guard | 安全防护 | 4.04 | 是 |
| surface_mapper | 攻击面测绘 | 7.98 | 是 |
| deep_finder | LLM 深挖 | 9.94 | 是 |
| candidate_screener | 候选筛选 | 2.64 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.77 | 是 |
| coordinator | 管线协调 | 5.14 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
