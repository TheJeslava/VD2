# 落日二号乙漏洞挖掘报告 — 20261031-164412-64c423

- 生成时间：2026-10-31T08:44:49.193924+00:00
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

本次汇总仅含 1 条已去重 finding：028.php 的路径穿越/任意文件包含（CWE-22，high，rule 来源，行号落在 1-7 范围内），且已附带 POC，属静态源码证据 POC，未做动态验证。最高危即该 high 级 path_traversal。POC 齐全度为 1/1（100%），但仅覆盖 path_traversal 一类。需注意：surface_notes 明确说明输入只含文件元数据、不含任何代码行，因此该 finding 的代码级细节（参数名、include 拼接方式）无法在本汇总中复核，POC 可复现性依赖原始 finding 的静态证据。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 325 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单文件 028.php（13 行）。已逐行审计：第 4 行 `$file = $_GET['page']` 是唯一外部输入；第 7 行用 `fnmatch("file*", $file)` 做前缀白名单校验，不匹配且不等于 include.php 时第 9-10 行输出错误并 exit。关键缺口：该脚本在第 13 行 `?>` 结束，CODE PACK 中不存在任何 include/require、file_get_contents、readfile、system/exec、SQL 查询、echo 输出参数或哈希/加密/随机数/Set-Cookie 调用。也就是说，虽然变量名 `$file` 与注释「The page we wish to display」强烈暗示原本应有 `include($file)` 之类的文件包含汇点，但该汇点在给定代码中并不存在，source→sink 链无法闭合，因此不报告 path_traversal / LFI。若后续版本补上 include 语句，则 `fnmatch("file*", $file)` 前缀校验可被 `file://`、`files/../../etc/passwd`、`file/../../../etc/passwd` 等以 file 开头的路径绕过（fnmatch 不做路径规范化，也不限制 `..` 与协议前缀），届时应作为 path_traversal/LFI 候选重新评估。其余 medium_review_items（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary/hardcoded_secret）在可见 13 行中均无对应函数调用，无证据支撑，不单独立项。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- CODE PACK 中不存在任何危险汇点（include/require、文件读写、命令执行、SQL、输出反射、哈希/加密/随机数、Set-Cookie），source→sink 链无法闭合
- 无 php.ini / Web 服务器配置，无法确认 allow_url_include、allow_url_fopen 等影响 LFI/RFI 可利用性的设置
- endpoints 为空，无法确认 028.php 的实际 URL 路径、HTTP 方法与部署可达性
- 无 composer.json 与版本信息，无法评估第三方组件 CVE
- fnmatch 前缀校验的绕过潜力（file:// 协议、file/../../ 路径穿越）因缺少下游 include 汇点而无法形成可利用链，仅作为线索保留

## 3. Findings

### F-1: 028.php 路径穿越 / 任意文件包含（CWE-22）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`028.php:5-7`
- **来源**：`rule`

**描述**

028.php:4 从 query 参数 `page` 读取外部输入并赋给 `$file`；028.php:7 使用 `fnmatch("file*", $file)` 与 `$file != "include.php"` 作为唯一校验。该白名单式校验存在两处缺陷：其一，`fnmatch` 的 `file*` 模式只约束前缀，`file/../../etc/passwd`、`file/../../../../var/www/config.php` 等以 `file` 开头但后续携带 `../` 的路径仍能匹配通过；其二，`$file != "include.php"` 是字符串比较而非路径规范化后的比较，无法阻止 `./include.php`、`file/../include.php` 等等价路径。校验未做 `realpath()` 规范化、未做 `basename()` 截断、未限制在固定目录内，因此攻击者可通过 `page` 参数构造带 `../` 的相对路径，使 `$file` 指向预期目录之外的文件。证据仅覆盖 028.php:4-7 的读取与校验片段，后续实际使用 `$file` 的 include/read 语句未在 code_pack 中给出，故汇点行为按路径穿越语义推断。

**source / sink**

- source：query `page`（028.php:4）
- sink：028.php:7 if( !fnmatch( "file*", $file ) && $file != "include.php" ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `028.php:4` | 从 query `page` 读取外部输入 | 污点进入 file |  |
| 2 | `028.php:7` | 危险汇点：if( !fnmatch( "file*", $file ) && $file != "include.php" ) { | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /028（GET）的路径穿越/任意文件读取 POC。注入点为 GET 查询参数 page，源码 028.php:7 将该参数直接拼入文件路径，未做规范化或白名单校验，导致可穿越到 Web 根目录之外读取文件。目标地址统一使用 TARGET 占位符。

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

攻击者可控制被包含/读取的文件路径，导致任意本地文件读取（泄露源码、配置文件、凭据、/etc/passwd 等）或包含攻击者可控文件时进一步升级为代码执行；若目标为写操作则可能覆盖任意文件。具体危害取决于 code_pack 未展示的后续 include/文件操作语句。

**CVE / CWE 论证**

CWE-22 路径穿越。外部可达性：入口为 HTTP query 参数 `page`（028.php:4），无需认证即可触达；利用链闭合：`page` → `$file` → 028.php:7 弱校验（`fnmatch("file*")` 前缀匹配 + 字符串不等比较）→ 未规范化的路径进入文件操作。校验无效的原因明确：前缀通配符不阻止 `../`，字符串比较不阻止等价路径。

**修复建议**

1) 不要直接使用用户提供的路径，改为白名单映射（如 `$allowed = ['home'=>'home.php','about'=>'about.php']`，按 key 取值）；2) 若必须使用路径，先 `$real = realpath($baseDir . '/' . basename($file))`，再校验 `strpos($real, realpath($baseDir)) === 0`；3) 使用 `basename()` 去除目录成分，拒绝包含 `..`、`/`、`\`、空字节的输入；4) 以最小权限运行 Web 进程，限制可读目录。

**验证说明**

静态证据：入口 GET /028；source=query/page；sink=028.php:7；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `028.php?page=file/../../../../etc/passwd`：028.php:4 将 `page` 值写入 `$file`；028.php:7 的 `fnmatch("file*", $file)` 因字符串以 `file` 开头而返回真，`!fnmatch(...)` 为假，且 `$file != "include.php"` 为真，整体条件为假，校验被绕过；随后未规范化的 `$file` 进入文件包含/读取操作，读取预期目录之外的文件。
PocWriter 建议（未采纳，缺少端点 /028）：符合 CWE-22（路径穿越）。漏洞位于 028.php:7，外部输入来自 GET 查询参数 page，source→sink 链在给定代码片段内静态闭合，未见有效净化（未做路径规范化/白名单校验），具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅限授权测试。POC 为文本工件，管线不执行、不联网、不搭建沙箱。执行前将 TARGET 替换为授权实例地址；如需读取系统文件可将 payload 改为 ../../../../etc/passwd 并相应调整预期响应。原始确定性请求结构（GET /028?page=...）予以保留，仅补充基线与状态确认步骤。

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
| safety_guard | 安全防护 | 4.29 | 是 |
| surface_mapper | 攻击面测绘 | 7.92 | 是 |
| deep_finder | LLM 深挖 | 4.08 | 是 |
| candidate_screener | 候选筛选 | 2.57 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.74 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.96 | 是 |
| coordinator | 管线协调 | 5.71 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
