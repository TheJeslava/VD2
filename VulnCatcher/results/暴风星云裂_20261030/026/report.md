# 落日二号乙漏洞挖掘报告 — 20261030-224819-27f4bb

- 生成时间：2026-10-30T14:48:50.474779+00:00
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

本次汇总仅含 1 条已去重 finding：026.php 中 ping 表单参数 ip 未过滤直接拼接进 shell_exec，类型 command_injection，严重度 critical，已附 POC（HTTP 型，可动态复现路径最短）。该条为本次最高危且唯一交付项，POC 齐全。其余攻击面（弱哈希/弱加密/弱随机/Cookie 标志/信任边界）在 surface_notes 中被列为待复核项，未形成 finding，属未覆盖而非已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 533 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已完整审计唯一源文件 026.php（21 行）。发现第 5 行 $_REQUEST['ip'] 未过滤直接拼接进第 10/14 行 shell_exec，构成回显型命令注入 RCE，链完整闭合。其余 medium_review_items（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）在文件中均无对应实现（无 md5/sha1、无加密调用、无随机数、无 setcookie、无头部信任），不成立。未覆盖：无 composer/框架/服务器配置，无法确认前置鉴权与部署路径；端点清单为空。

未覆盖 / 证据缺口：
- 无 Web 服务器/路由配置，无法确认 026.php 公网暴露路径与前置鉴权
- 无部署描述，无法确认运行用户权限（影响危害等级）
- 端点清单为空

## 3. Findings

### F-1: 026.php ping 表单参数 ip 未过滤直接拼接进 shell_exec 导致远程命令执行

- **类型**：`command_injection` / CWE-78
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`026.php:5-14`
- **来源**：`llm_finding`

**描述**

026.php 在收到 POST 参数 Submit 后，从 $_REQUEST['ip'] 读取用户输入（第 5 行），未做任何白名单、转义（escapeshellarg/escapeshellcmd）或类型校验，直接以字符串拼接方式传入 shell_exec('ping -c 4 ' . $target)（*nix，第 14 行）或 shell_exec('ping  ' . $target)（Windows，第 10 行）。攻击者可在 ip 参数中注入 shell 元字符（;、|、&&、$()、反引号）执行任意系统命令，命令输出经 $cmd 回显到页面 <pre> 中（第 18 行），形成完整的回显型 RCE。

**source / sink**

- source：body `ip`（026.php:5）
- sink：026.php:14 shell_exec('ping  -c 4 ' . $target)（第 14 行）/ shell_exec('ping  ' . $target)（第 10 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `026.php:3` | 检测到 POST 参数 Submit 存在，进入漏洞分支 | 请求进入处理逻辑 |  |
| 2 | `026.php:5` | 从 $_REQUEST['ip'] 读取攻击者可控输入并赋给 $target，无任何过滤 | 原始字符串，完全可控 |  |
| 3 | `026.php:8` | 通过 php_uname('s') 判断操作系统，选择对应分支（不影响注入） | 分支选择 |  |
| 4 | `026.php:14` | 将 $target 直接字符串拼接到 ping 命令后交给 shell_exec 执行（*nix 分支） | 拼接进 shell 命令字符串，元字符被 shell 解释 | 无 escapeshellarg/escapeshellcmd、无白名单、无输入校验 |
| 5 | `026.php:18` | 命令执行结果 $cmd 回显到页面 <pre> 标签，攻击者可直接读取命令输出 | 命令输出回显 |  |

**POC**

针对 /026.php（POST）的 OS 命令注入 POC。注入点为 POST 参数 ip，源码 026.php:14 将外部输入拼接进系统命令执行；payload 使用 TARGET 占位符，仅限授权测试。

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
- 执行状态：未执行（`executed=False`）

**影响**

未认证攻击者可在服务器上以 Web 进程权限执行任意系统命令，完全控制主机、读取敏感文件、横向移动。

**CVE / CWE 论证**

CWE-78 OS 命令注入。外部可达（HTTP POST 参数 ip），无需认证，source→sink 链完整闭合，命令输出直接回显，属典型高危 RCE。

**修复建议**

使用 escapeshellarg() 对 $target 转义，或改用白名单校验（仅允许合法 IP/域名正则），并优先使用参数数组形式调用（如 proc_open 传数组）避免 shell 解释。

**验证说明**

需动态确认 026.php 实际暴露路径与 Web 进程权限；源码层面注入链已完全闭合。
模型 POC 要点：向 026.php 提交 ip 参数，利用 ; 或 | 分隔符在 ping 命令后追加任意系统命令，输出回显在页面中。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /026.php）：符合 CWE-78（OS 命令注入）。漏洞位于可交付代码 026.php:14，外部输入来自 POST body 参数 ip，source→sink 链已静态闭合，未发现有效净化；具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。目标地址统一使用 TARGET 占位符，替换为授权测试目标后手动执行。原始 HTTP 请求：POST /026.php HTTP/1.1，Host: TARGET:8080，Content-Type: application/x-www-form-urlencoded，Content-Length: 8，body 为 ip=%3Bid。禁止用于未授权目标。

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
| safety_guard | 安全防护 | 3.82 | 是 |
| surface_mapper | 攻击面测绘 | 7.24 | 是 |
| deep_finder | LLM 深挖 | 7.5 | 是 |
| candidate_screener | 候选筛选 | 2.84 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 3.98 | 是 |
| coordinator | 管线协调 | 5.09 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
