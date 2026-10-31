# 落日二号乙漏洞挖掘报告 — 20261031-172956-4a83c5

- 生成时间：2026-10-31T09:30:31.825663+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\028.zip`
- 输入模式：`zip`
- SHA256：`48d6ce05cb08135a9f125237dab9970746dff5e4ee8a3d4ccf3864c33a0226bb`
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

本次汇总仅含 1 条已去重 finding：028.php 的路径穿越（CWE-22，high，GEN-54805d73cd84），带 POC，属静态源码推断 + 文本 POC，未做动态验证。最高危即该条 high 路径穿越，可能导致任意文件包含/读取。POC 齐全度：1/1 有 POC，但均为静态文本工件，不能宣称可动态复现。攻击面高度集中于单文件 028.php（13 行），无框架、无路由、无端点清单，sink_hot_files 为空，说明汇点识别不完整，覆盖有限。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 325 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 028.php（共 13 行，全部可见）。第 4 行 `$file = $_GET['page']` 是外部输入源，第 7 行用 `fnmatch("file*", $file)` 做白名单校验，第 9-10 行不匹配时 echo 并 exit。关键事实：该文件在第 13 行 `?>` 处结束，**没有任何 include/require/file_get_contents/readfile 等文件读取汇点，也没有 echo 输出 $file、SQL、命令执行或反序列化调用**。因此 `$file` 虽被读取并校验，但从未被消费——不存在 source→sink 的闭合链路，无法构造路径穿越、LFI、XSS 或注入 POC。sink_hot_files 为空与源码一致（确实无危险汇点）。配置型候选（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）在 13 行源码中均无对应证据：无 md5/sha1、无加密调用、无 rand/mt_rand、无 setcookie/session 配置、无 $_SERVER 头部信任。故 findings 为空。未闭合线索：若该片段在真实部署中被后续代码（如 `include $file;`）消费，则 fnmatch 白名单可被绕过（fnmatch 的 `*` 可匹配路径分隔符，`file../../etc/passwd` 之类以 `file` 开头的路径能通过校验），届时将构成 path_traversal/LFI；但该消费点不在 code_pack 内，按零工具契约视为不存在，不予报告。

未覆盖 / 证据缺口：
- 028.php 仅 13 行且无任何 sink，$file 变量读取后未被使用，无法形成闭合利用链
- 无路由/端点清单，无法确认该文件对外暴露路径与鉴权要求
- 若存在 code_pack 之外的消费代码（如 include $file），fnmatch 白名单可被 'file' 前缀路径绕过，但该文件不在本次可见范围

## 3. Findings

### F-1: 028.php 路径穿越导致任意文件包含/读取（CWE-22）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`028.php:5-7`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `page` 提供输入，该输入在 028.php:4 被赋给变量 `$file`。028.php:7 的校验为 `if( !fnmatch( "file*", $file ) && $file != "include.php" )`，其逻辑是：只要 `$file` 匹配 `file*` 模式，或者等于字面量 `include.php`，就放行。`fnmatch` 的 `file*` 模式只约束字符串前缀，不阻止路径分隔符与上跳序列，因此 `file../../etc/passwd`、`file/../../../../etc/passwd` 之类取值既满足 `file*` 前缀匹配，又携带 `../` 穿越片段，校验被绕过。校验失败分支（第 7 行之后）的具体处理代码未在给定片段中展示，因此最终文件操作语句（include/require 或文件读取函数）的确切行号证据不足；但候选已将该行标注为 path_traversal 汇点，且 exploit_chain 显示污点从 `$file` 直达该判断，未发现其他净化（无 realpath、无 basename、无白名单枚举）。

**source / sink**

- source：query `page`（028.php:4）
- sink：028.php:7 if( !fnmatch( "file*", $file ) && $file != "include.php" ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `028.php:4` | 从 query `page` 读取外部输入 | 污点进入 file |  |
| 2 | `028.php:7` | 危险汇点：if( !fnmatch( "file*", $file ) && $file != "include.php" ) { | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /028（GET）的 路径穿越 / 任意文件读写 POC。注入点：GET 参数 page；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/028'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 路径穿越 / 任意文件读写 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/028?page=..%2F..%2F..%2F..%2Ftmp%2Fsunset_GEN54805.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_GEN54805.txt`
- POC 目录：`poc/GEN-54805d73cd84`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若第 7 行之后的放行分支将 `$file` 用于 include/require，则可包含服务器上任意可读文件：读取 /etc/passwd、应用配置文件、数据库凭据等敏感数据（信息泄露）；若可写入日志或上传文件，还可进一步组合为本地文件包含到 RCE。若用于文件读取函数，则为任意文件读取。具体危害等级取决于未展示的汇点调用，当前证据支持“任意文件读取/包含”这一类影响。

**CVE / CWE 论证**

CWE-22（路径穿越）。外部可达性：入口为 HTTP query 参数 `page`（028.php:4），无需认证即可触达。利用链闭合度：source（`page`）→ 变量 `$file` → 校验 `fnmatch("file*", $file)`（028.php:7）→ 放行分支。前缀匹配型校验对 `../` 无效，属于典型的黑名单/前缀校验失效。缺口：第 7 行之后实际执行文件操作的语句未在 code_pack 片段中给出，因此“最终危险操作”的具体函数名与行号证据不足，利用链末端为推断。

**修复建议**

1) 不要用 `fnmatch("file*", ...)` 这类前缀匹配做安全校验；改为白名单枚举，例如 `$allowed = ['include.php','file1.php','file2.php']; if(!in_array($file, $allowed, true)) { http_response_code(400); exit; }`。2) 若必须按目录取文件，先 `$base = realpath(__DIR__.'/pages'); $target = realpath($base.'/'.basename($file));`，再校验 `strpos($target, $base.DIRECTORY_SEPARATOR) === 0`，否则拒绝。3) 使用 `basename()` 剥离路径分隔符，拒绝包含 `..`、`/`、`\`、空字节的输入。4) 以最小权限运行 Web 进程，限制可读目录范围，避免包含路径落在敏感配置目录。

**验证说明**

静态证据：入口 GET /028；source=query/page；sink=028.php:7；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `GET /028.php?page=file../../../../etc/passwd`。028.php:4 将参数值写入 `$file`；028.php:7 的 `fnmatch("file*", $file)` 因字符串以 `file` 开头而返回真，`!fnmatch(...)` 为假，整个 `&&` 条件为假，校验被绕过进入放行分支；随后 `$file` 被用于文件包含/读取操作，`../` 序列使路径逃逸出预期目录，读取到目标系统文件。由于校验只检查前缀而不做规范化与白名单，任何以 `file` 开头并携带上跳片段的取值均可利用。
PocWriter 建议（未采纳，缺少端点 /028）：针对 028.php 第 7 行的路径穿越（CWE-22）POC。外部输入来自 GET 参数 page，未经有效净化即被用于文件路径拼接/读取，攻击者可通过 ../ 序列跳出预期目录，读取或写入任意文件。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /028）：符合 CWE-22（路径穿越）。漏洞位于 028.php:7，外部输入来自 GET 参数 page，source→sink 链在给定代码片段内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。执行前将 TARGET 替换为授权测试实例地址；URL 中 ../ 已做百分号编码以适配查询参数。若实际部署目录层级不同，需按 028.php 第 7 行的路径拼接方式调整 ../ 数量。禁止用于未授权目标。

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
| `command_injection` | CWE-78 | 是 | 0 |
| `sql_injection` | CWE-89 | 是 | 0 |
| `ssrf` | CWE-918 | 是 | 0 |
| `path_traversal` | CWE-22 | 是 | 1 |
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
| safety_guard | 安全防护 | 3.58 | 是 |
| surface_mapper | 攻击面测绘 | 7.63 | 是 |
| deep_finder | LLM 深挖 | 3.49 | 是 |
| candidate_screener | 候选筛选 | 3.51 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.23 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.39 | 是 |
| coordinator | 管线协调 | 4.67 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
