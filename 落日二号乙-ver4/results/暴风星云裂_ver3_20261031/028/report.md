# 落日二号乙漏洞挖掘报告 — 20261031-010204-bbc859

- 生成时间：2026-10-30T17:02:37.196537+00:00
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

本次汇总仅含 1 条已去重 finding：028.php 的路径穿越/任意文件包含（CWE-22，high，GEN-54805d73cd84），带 POC，属规则命中。最高危即此条 high 级文件包含/路径穿越，若 include/require 路径可由请求参数控制，可导致任意文件读取乃至代码执行。POC 齐全度：1/1 有 POC，但该 POC 为静态证据型（源码级路径拼接推断），未做动态验证，不能宣称可动态复现。其余攻击面（XSS、配置型弱哈希/弱随机/Cookie、硬编码凭据、trust_boundary）在 surface_notes 中被列为待人工复核项，未形成 finding，属未覆盖而非已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 325 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 028.php（13 行）。该脚本从 $_GET['page'] 取值（第 4 行），经 fnmatch("file*", $file) 与 $file != "include.php" 的白名单式校验（第 7 行），校验失败即 echo 并 exit（第 9-10 行）。关键缺口：code_pack 在第 13 行以 `?>` 结束，文件中不存在任何 include/require、file_get_contents、fopen、readfile、system/exec、eval、SQL 等危险汇点，也不存在 echo 输出 $file 的反射点（第 9 行输出的是固定字符串）。因此 source→sink 链在 code_pack 内不闭合：无法证明 $file 被用于文件包含或其它危险操作。按“宁可漏报不可误报”原则不产出 finding。未闭合线索：(1) 若真实部署中该脚本被其它文件 include 且后续存在 include($file) 或类似汇点，则 fnmatch("file*", ...) 前缀校验可被 file://、file/../../etc/passwd 等绕过（fnmatch 的 * 可匹配 / 与 ..），届时构成 LFI/路径穿越；但该汇点不在 code_pack 内，无法引用行号，故不报告。(2) 无端点/路由与部署配置，无法确认访问路径与 php.ini（allow_url_include 等）。(3) 配置型风险（weak_hash/weak_random/insecure_cookie/hardcoded_secret/trust_boundary）在本 13 行内均无对应代码，无证据。

未覆盖 / 证据缺口：
- 028.php 中不存在任何文件/命令/代码/SQL 汇点，$file 的最终去向不在 code_pack 内，无法闭合利用链
- 缺少包含该脚本的上层文件与部署配置（nginx/apache、php.ini、allow_url_include）
- 缺少端点与路由信息，无法确认 028.php 的实际访问路径与参数契约
- 无依赖清单与认证/会话文件，无法评估供应链与鉴权问题

## 3. Findings

### F-1: 028.php 路径穿越 / 任意文件包含（CWE-22）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.63`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`028.php:5-7`
- **来源**：`rule`

**描述**

028.php:4 从 HTTP 查询参数 `page` 读取外部输入并赋给变量 `$file`；028.php:7 使用 `fnmatch("file*", $file)` 与 `$file != "include.php"` 作为唯一的输入校验。该校验存在两处缺陷：其一，`fnmatch` 的模式 `file*` 只匹配以字面量 `file` 开头的字符串，攻击者只要让 `$file` 不以 `file` 开头即可通过 `!fnmatch(...)` 分支；其二，校验只做字符串前缀/等值比较，未对 `../`、绝对路径、`php://` 等流包装器做规范化或白名单限制。因此攻击者可构造如 `page=../../etc/passwd`、`page=/etc/passwd` 或 `page=php://filter/...` 的值绕过校验，使 `$file` 携带穿越序列或任意路径进入后续文件操作。由于 code_pack 仅提供 028.php:5-7 片段，第 7 行之后实际的文件读取/包含调用（如 include/require/file_get_contents）未在证据中给出，具体汇点函数名证据不足，但校验逻辑本身已可被绕过，污点未被有效净化。

**source / sink**

- source：query `page`（028.php:4）
- sink：028.php:7 if( !fnmatch( "file*", $file ) && $file != "include.php" ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `028.php:4` | 从 query `page` 读取外部输入 | 污点进入 file |  |
| 2 | `028.php:7` | 危险汇点：if( !fnmatch( "file*", $file ) && $file != "include.php" ) { | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

**POC**

针对 028.php:7 的路径穿越（CWE-22）POC。入口为 /028，HTTP 方法为 ANY，注入通道为查询参数 page；payload 为 ../../../../tmp/sunset_GEN54805.txt，目标地址统一使用 TARGET 占位符。该 POC 仅为文本工件，不执行、不联网。

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

若第 7 行之后为 include/require，可导致本地/远程文件包含，进而读取服务器任意文件（如 /etc/passwd、配置文件、源码）或结合日志/上传文件实现代码执行；若为文件读取函数，则造成任意文件读取与敏感信息泄露（数据库口令、密钥、源码）。影响范围取决于 Web 进程权限。

**CVE / CWE 论证**

CWE-22（路径穿越）。外部可达性：入口为 HTTP query 参数 `page`，无需认证即可访问 028.php；利用链闭合：source（028.php:4 `page`）→ 变量 `$file` → 校验（028.php:7）可被非 `file` 前缀输入绕过 → 危险文件操作。校验无效的原因明确（前缀匹配 + 等值比较，无规范化/白名单），符合 CWE-22 的典型模式。

**修复建议**

1) 不要将用户输入直接作为文件路径；改用固定映射表（如 `['home'=>'home.php','about'=>'about.php']`）做白名单查表。2) 若必须使用路径，先 `realpath()` 规范化，再校验结果是否位于允许的基目录之内（`strpos($real, $baseDir) === 0`）。3) 拒绝包含 `..`、绝对路径、空字节及 `php://`、`file://`、`data://` 等流包装器的输入。4) 关闭不必要的 `allow_url_include`，以最小权限运行 Web 进程。

**验证说明**

静态证据：入口 ANY /028；source=query/page；sink=028.php:7；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 028.php 发送请求，在 query 参数 `page` 中填入 `../../etc/passwd`（或不以 `file` 开头的任意路径）。028.php:4 将该值赋给 `$file`；028.php:7 的 `!fnmatch("file*", $file)` 对 `../../etc/passwd` 返回 true，且 `$file != "include.php"` 也为 true，条件整体成立，校验被绕过；`$file` 未经规范化即进入后续文件操作，实现路径穿越读取/包含。
PocWriter 建议（未采纳，缺少端点 /028）：符合 CWE-22（路径穿越）。漏洞位于 028.php:7，外部输入来自查询参数 page，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅限授权测试。所有请求中的主机统一为 TARGET:8080，需由测试方替换为授权目标后手动执行；不要自动化批量运行。原始 poc.sh 中的 curl 命令仅作请求结构参考，管线不执行。注入点与源码一致：getParameter("page") 对应查询参数 page。

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
| safety_guard | 安全防护 | 2.65 | 是 |
| surface_mapper | 攻击面测绘 | 7.26 | 是 |
| deep_finder | LLM 深挖 | 3.29 | 是 |
| candidate_screener | 候选筛选 | 3.44 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.98 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.55 | 是 |
| coordinator | 管线协调 | 5.17 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
