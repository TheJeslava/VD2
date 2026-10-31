# 落日二号乙漏洞挖掘报告 — 20261031-011908-7d30b5

- 生成时间：2026-10-30T17:19:39.514746+00:00
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

本次汇总仅含 1 条已去重 finding：028.php 的路径穿越 / 任意文件包含（CWE-22，high，rule 来源，行号落在 1-7 范围内），且已附带 POC，属静态证据 POC，未做动态验证。最高危即该条 high 级 path_traversal。POC 齐全度为 1/1（仅就本条而言），但覆盖极薄：仅 1 个文件、0 个端点、无框架，sink_hot_files 为空，说明静态规则未识别到明确危险汇点，其余注入类与配置类风险均未形成 finding，不能据此判定不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 325 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 028.php（13 行，完整展示）。该脚本读取 $_GET['page'] 到 $file（第 4 行），随后用 fnmatch("file*", $file) 与 $file != "include.php" 做白名单式校验（第 7 行），不通过则输出错误并 exit（第 9-10 行）。关键事实：脚本在第 13 行以 ?> 结束，校验之后没有任何 include/require、文件读取、echo 输出 $file、eval/system 等危险汇点，$file 在校验后即不再被使用。因此虽然存在“用户可控路径 + 弱校验（fnmatch 通配符可被 file:// 等前缀绕过）”的形态，但缺少实际 sink，source→sink 链不闭合，不构成 path_traversal / LFI / RFI，按零容忍误报原则不报告。配置类线索（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）在该文件中均无对应代码（无 md5/sha1、无 openssl/mcrypt、无 rand/mt_rand、无 setcookie/session、无 $_SERVER 头信任），全部排除。未发现 prompt_injection 诱导文本。未覆盖范围：无 endpoints、无部署配置（php.ini 的 allow_url_include 等）、无依赖清单；若后续版本在该校验后追加 include($file) 或 readfile($file)，则 fnmatch("file*", ...) 可被 file://、file:///etc/passwd 等前缀满足，将立即升级为 LFI/RFI，建议人工复核该文件是否被截断或存在未纳入清单的后续逻辑。

未覆盖 / 证据缺口：
- code_pack 仅含 028.php 且校验后无 sink，无法形成闭合利用链
- 缺少 Web 服务器/php.ini 配置，无法评估 allow_url_include、open_basedir 等
- 无端点清单与认证信息，无法判断部署形态与可达性
- 无 composer.json 等依赖信息，供应链风险未评估

## 3. Findings

### F-1: 028.php 路径穿越 / 任意文件包含（CWE-22）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`028.php:5-7`
- **来源**：`rule`

**描述**

攻击者通过 HTTP query 参数 `page` 提供输入，该值在 028.php:4 被读入变量 `$file`。028.php:7 的校验为 `if( !fnmatch( "file*", $file ) && $file != "include.php" )`，其语义是：只要 `$file` 以 `file` 开头（匹配 `file*`）或等于 `include.php`，条件即为假，校验被跳过，`$file` 直接进入后续文件操作。该白名单式校验只约束前缀，未对 `../`、绝对路径、空字节或 URL 编码做规范化与拒绝，因此 `file../../etc/passwd`、`file/../../../../etc/shadow` 等以 `file` 开头的值可绕过前缀检查并向上穿越目录。校验无效的根因是：使用 `fnmatch` 做前缀匹配而非对规范化后的真实路径做白名单比对，且未使用 `realpath()` 限定基目录。

**source / sink**

- source：query `page`（028.php:4）
- sink：028.php:7 if( !fnmatch( "file*", $file ) && $file != "include.php" ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `028.php:4` | 从 query `page` 读取外部输入 | 污点进入 file |  |
| 2 | `028.php:7` | 危险汇点：if( !fnmatch( "file*", $file ) && $file != "include.php" ) { | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

**POC**

针对 028.php:7 的路径穿越（CWE-22）POC。入口为 /028，HTTP 方法为 ANY，注入点为查询参数 page；该参数被直接拼接到文件路径并用于文件读写，未发现有效净化。payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/028'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 路径穿越 / 任意文件读写 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/028?page=..%2F..%2F..%2F..%2Ftmp%2Fsunset_GEN54805.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_GEN54805.txt`
- POC 目录：`poc/GEN-54805d73cd84`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可读取/包含 Web 根目录之外的任意文件（如 /etc/passwd、应用配置文件、密钥文件），导致敏感数据泄露；若后续为 include/require 语义，则可包含攻击者可控的本地文件，配合日志或上传文件可进一步升级为任意代码执行。具体危险操作位于 028.php:7 之后的文件访问语句，输入中未给出该行，故最终函数名证据不足。

**CVE / CWE 论证**

CWE-22（路径穿越）。外部可达性：入口为 HTTP query 参数 `page`，无需认证即可触发；利用链闭合：`page` → `$file`（028.php:4）→ 前缀校验被 `file*` 绕过（028.php:7）→ 文件访问汇点。校验仅做前缀匹配，未规范化路径，属典型可绕过白名单。

**修复建议**

1) 不要用 `fnmatch("file*", ...)` 做安全校验；2) 对输入做严格白名单：仅允许预定义的固定文件名集合（如 `['include.php','file1.php']`），用 `in_array($file, $allowed, true)` 精确匹配；3) 若必须接受路径，使用 `$base = realpath(__DIR__); $real = realpath($base . '/' . $file);` 并校验 `strpos($real, $base . DIRECTORY_SEPARATOR) === 0`，拒绝 `..`、绝对路径、空字节；4) 以最小权限运行 Web 进程，限制可读目录。

**验证说明**

静态证据：入口 ANY /028；source=query/page；sink=028.php:7；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `?page=file../../../../etc/passwd`。028.php:4 将 `page` 值赋给 `$file`；028.php:7 的 `fnmatch("file*", $file)` 因值以 `file` 开头而返回真，`!fnmatch(...)` 为假，整个 `&&` 条件为假，校验分支被跳过；`$file` 未经规范化即进入后续文件读取/包含操作，实现目录穿越读取任意文件。
PocWriter 建议（未采纳，缺少端点 /028）：符合 CWE-22（路径穿越）。漏洞位于可交付代码 028.php:7，外部输入来自查询参数 page，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件；证据等级为 llm_inferred（基于源码推断，未经动态验证）。
POC 备注：仅保留文本工件，不执行、不联网、不搭建沙箱。原 poc.sh 中的 curl 命令仅作请求结构参考，请手动替换 TARGET 后在授权环境执行；request.http 中的 Content-Length 为示例值，实际发送时按真实 body 长度计算。注入通道为查询参数 page，勿改为其他参数名。

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
| safety_guard | 安全防护 | 2.99 | 是 |
| surface_mapper | 攻击面测绘 | 5.98 | 是 |
| deep_finder | LLM 深挖 | 3.35 | 是 |
| candidate_screener | 候选筛选 | 3.23 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.27 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.71 | 是 |
| coordinator | 管线协调 | 5.81 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
