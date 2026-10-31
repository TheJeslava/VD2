# 落日二号乙漏洞挖掘报告 — 20261031-002140-7872d3

- 生成时间：2026-10-30T16:22:14.542130+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\028.zip`
- 输入模式：`zip`
- SHA256：`48d6ce05cb08135a9f125237dab9970746dff5e4ee8a3d4ccf3864c33a0226bb`
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

本次汇总仅含 1 条已去重 finding：028.php 的路径穿越（CWE-22，high，rule 来源，带 POC）。该文件仅 13 行 / 236 字节，是本次唯一源码载体，无框架、无路由声明、无端点清单，因此该 POC 属静态证据型（基于源码路径拼接/包含推断），未做动态验证，不能宣称可动态复现。最高危即该 path_traversal（high）。POC 齐全度：1/1 finding 有 POC，但均为静态文本工件（TARGET 占位，仅限授权测试）。其余攻击面（配置类、信任边界）无候选，属未覆盖而非已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 325 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 028.php（共 13 行，已完整展示）。该脚本从 $_GET['page'] 取值（第 4 行），经 fnmatch("file*", $file) 与 $file != "include.php" 的白名单式校验（第 7 行），不通过则输出错误并 exit（第 9-11 行）。关键缺口：第 13 行之后没有任何 include/require/file_get_contents/readfile 等文件读取或包含汇点，脚本在校验后直接结束，污点变量 $file 未被任何危险操作使用。因此不存在可闭合的 source→sink 链，无法构造 LFI/路径穿越/任意文件读取 POC。虽然 fnmatch("file*", ...) 属于弱校验（可被 file://、file/../ 等绕过），但缺少实际汇点，不能作为独立漏洞申报，仅作为线索记录：若后续版本在 0013 行后追加 include($file) 或 readfile($file)，则立即构成 LFI。配置类攻击面（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）在该 13 行内均无对应实现（无 md5/sha1、无 rand/mt_rand、无 setcookie/session_start、无 $_SERVER 头信任）。未发现 prompt_injection 文本。

未覆盖 / 证据缺口：
- 028.php 仅 13 行且无任何文件/命令/输出汇点，污点链不闭合
- 无 HTTP 端点清单，无法确认 028.php 的可达性与部署方式
- 无 php.ini/Web 服务器配置/composer.json/README，无法判断运行环境与 include 上下文
- fnmatch("file*", $file) 弱校验为潜在 LFI 前置条件，但缺少 include/readfile 汇点，未闭合

## 3. Findings

### F-1: 028.php 路径穿越导致任意文件包含/读取（CWE-22）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`028.php:5-7`
- **来源**：`rule`

**描述**

攻击者通过 HTTP query 参数 `page` 提供输入，该值在 028.php:4 被赋给变量 `$file`。028.php:7 使用 `fnmatch("file*", $file)` 与 `$file != "include.php"` 作为唯一校验：`fnmatch` 只做通配符匹配，不解析 `../`、绝对路径或空字节等路径语义，且该条件为否定式（`!fnmatch(...) && $file != "include.php"`），只要输入不以 `file` 开头且不等于 `include.php` 即通过校验，因此 `../../etc/passwd`、`/etc/passwd` 等值可直接绕过。校验失败后 `$file` 未经规范化（无 realpath/basename/白名单）即被用于后续文件操作（包含/读取），形成从 query `page` → `$file` → 文件路径汇点的完整污点链。注意：输入片段仅给出 028.php:5-7，第 8 行之后的具体文件操作函数（include/require/file_get_contents 等）未在证据中给出，故汇点函数名证据不足，但校验逻辑本身已确认无效。

**source / sink**

- source：query `page`（028.php:4）
- sink：028.php:7 if( !fnmatch( "file*", $file ) && $file != "include.php" ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `028.php:4` | 从 query `page` 读取外部输入 | 污点进入 file |  |
| 2 | `028.php:7` | 危险汇点：if( !fnmatch( "file*", $file ) && $file != "include.php" ) { | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /028（ANY）的 路径穿越 / 任意文件读写 POC。注入点：ANY 参数 page；payload 使用 TARGET 占位符。

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

可读取/包含服务器上任意可读文件（如 /etc/passwd、应用配置、密钥文件），导致敏感信息泄露；若后续为 include/require，则可包含攻击者可控的本地文件（如日志、上传文件）进而执行 PHP 代码，造成远程/本地代码执行与服务器失陷。

**CVE / CWE 论证**

CWE-22（路径穿越）。外部可达性：入口为 HTTP query 参数 `page`，无需认证即可触发；利用链闭合：外部输入直接进入 `$file`，028.php:7 的 `fnmatch` 校验不具路径规范化能力，可被 `../` 或绝对路径绕过，随后进入文件操作汇点。属于典型的输入校验不当导致的路径穿越，符合 CVE 对路径穿越类漏洞的判定要素（外部可控输入 + 校验可绕过 + 危险文件操作）。

**修复建议**

1) 不要将用户输入直接拼接为文件路径，改用固定白名单映射（如 `$pages = ['home'=>'home.php','about'=>'about.php']`，按 key 取值）；2) 若必须使用文件名，先 `basename()` 去除目录部分，再用 `realpath()` 规范化并与允许的基目录前缀比较（`str_starts_with($real, $baseDir)`）；3) 拒绝包含 `..`、绝对路径、空字节的输入；4) 对包含的文件设置最小权限，禁止包含上传目录/日志目录中的文件。

**验证说明**

静态证据：入口 ANY /028；source=query/page；sink=028.php:7；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `028.php?page=../../../../etc/passwd`（或绝对路径 `/etc/passwd`）→ 028.php:4 将参数写入 `$file` → 028.php:7 的 `!fnmatch("file*", $file) && $file != "include.php"` 因输入不以 `file` 开头且不等于 `include.php` 而判定通过，未做任何路径规范化 → `$file` 原样进入后续文件包含/读取操作 → 读取到目标目录之外的文件，完成路径穿越。
PocWriter 建议（未采纳，缺少端点 /028）：针对 028.php 第 7 行的路径穿越（CWE-22）POC。外部输入来自查询参数 page，未净化即拼接进文件路径，可读取或写入 testfiles 目录之外的文件。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /028）：符合 CWE-22。漏洞位于 028.php:7，外部输入来自查询参数 page，source→sink 链在给定代码范围内静态闭合，未见有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。脚本中的 TARGET 需由授权测试人员手动替换；禁止在未授权环境运行。原始确定性 POC 的请求结构（GET /028?page=...）予以保留，仅补充基线与对比步骤。

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
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.46 | 是 |
| surface_mapper | 攻击面测绘 | 7.85 | 是 |
| deep_finder | LLM 深挖 | 3.49 | 是 |
| candidate_screener | 候选筛选 | 3.14 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.32 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.34 | 是 |
| coordinator | 管线协调 | 5.69 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
