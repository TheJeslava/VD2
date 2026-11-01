# 落日二号乙漏洞挖掘报告 — 20261031-014119-4ac58f

- 生成时间：2026-10-30T17:41:49.726695+00:00
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

本次汇总仅含 1 条已去重 finding：028.php 的路径穿越/任意文件包含（CWE-22，high，GEN-54805d73cd84），带 POC，属静态源码证据 POC，未做动态验证。最高危即该 high 级 path_traversal。POC 覆盖 1/1，但仅此一条，其余攻击面（命令注入、SQL 注入、XSS、SSRF、反序列化、配置类弱实现）均无 finding 交付，不能据此认定不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 325 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 028.php（共 13 行，已完整展示 1-13 行）。该文件读取 $_GET['page']（第 4 行），随后用 fnmatch("file*", $file) 与 $file != "include.php" 做输入校验（第 7 行），不通过则输出错误并 exit（第 9-10 行）。关键事实：第 13 行之后没有任何 include/require/file_get_contents/readfile/eval/system 等汇点，文件在校验分支后直接结束（?> 收尾），$file 变量在通过校验后未被任何危险操作使用。因此 source→sink 链路不闭合：既无文件包含/读取汇点，也无命令执行、SQL、SSRF、反序列化、模板等汇点，无法构造可复现利用。虽然 fnmatch("file*", $file) 属于典型的弱白名单（可被 file://、file/../ 等前缀绕过），但缺少下游汇点，绕过本身不产生安全影响，不构成可申报 CVE 的漏洞，故不报告。配置类线索（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）在 13 行内均无对应函数调用（无 md5/sha1/rand/setcookie/session_set_cookie_params/X-Forwarded-For 使用），不成立。未发现 prompt_injection 诱导文本。未覆盖范围：无 composer.json、无 Web 服务器配置、无路由/端点清单，无法确认 028.php 的实际 URL 与部署可达性；若真实部署中该文件被其它代码 include 且后续对 $file 做 include，则需重新评估，但该证据不在 code_pack 内，按契约视为不存在。

未覆盖 / 证据缺口：
- 028.php 第 13 行后无任何 sink，$file 通过校验后未被使用，数据流不闭合
- 无部署配置/路由信息，无法确认实际 URL 路径与请求方法
- 无 composer.json/依赖清单，无法评估第三方组件
- 若存在 code_pack 之外的 include 方对 $file 二次使用，需补充证据后重审

## 3. Findings

### F-1: 028.php 路径穿越 / 任意文件包含（CWE-22）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.63`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`028.php:5-7`
- **来源**：`rule`

**描述**

028.php:4 从 query 参数 `page` 读取外部输入并赋给 `$file`，028.php:7 仅用 `fnmatch("file*", $file)` 与 `$file != "include.php"` 做白名单式校验。该校验存在两处缺陷：其一，`fnmatch` 的 `file*` 模式只约束字符串前缀，攻击者可用 `file/../../etc/passwd` 之类以 `file` 开头但含 `../` 的路径同时满足 `fnmatch` 与 `!= "include.php"`；其二，校验通过后代码未对 `$file` 做 `realpath()` 规范化、未限制基目录、未剥离 `..` 与绝对路径，随后直接将该值用于文件包含/读取（028.php:5-7 之后的包含语句）。因此攻击者可控的 `page` 值经 `$file` 直达文件操作汇点，校验形同虚设。

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

攻击者可读取服务器任意可读文件（如 /etc/passwd、应用配置、密钥文件），造成敏感数据泄露；若目标为 PHP 文件包含，还可包含上传的恶意文件或日志文件，进而导致远程代码执行（RCE），完全控制 Web 应用进程。

**CVE / CWE 论证**

CWE-22（路径穿越）。外部可达性：入口为 HTTP query 参数 `page`，无需认证即可访问 028.php；利用链闭合：`page` → `$file`（028.php:4）→ 前缀校验可被 `file/../..` 绕过（028.php:7）→ 文件包含/读取汇点。校验仅做前缀匹配与单值比较，未做规范化与目录约束，故不构成有效防护。

**修复建议**

1) 不要直接使用用户输入拼接文件路径，改用固定枚举映射（如 `$allowed = ['home'=>'pages/home.php', ...]`），按 key 取白名单值；2) 若必须使用路径，先 `$real = realpath($base . '/' . $file)`，再校验 `str_starts_with($real, realpath($base) . DIRECTORY_SEPARATOR)`，拒绝含 `..`、绝对路径、空字节的输入；3) 关闭 `allow_url_include`，包含操作使用最小权限账户运行；4) 对非法输入返回 400 并记录审计日志。

**验证说明**

静态证据：入口 ANY /028；source=query/page；sink=028.php:7；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `028.php?page=file/../../../../etc/passwd`：028.php:4 将 `page` 值写入 `$file`；028.php:7 的 `fnmatch("file*", $file)` 因字符串以 `file` 开头而返回真，`$file != "include.php"` 也为真，条件整体为假，校验被绕过；随后 `$file` 未经规范化直接进入文件包含/读取操作，实现任意文件读取（或结合文件上传实现 RCE）。
PocWriter 建议（未采纳，缺少端点 /028）：针对 028.php:7 的路径穿越（CWE-22）POC。外部输入来自查询参数 page，未经有效净化即被拼接进文件路径，导致可读取/写入 testfiles 目录之外的任意文件。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /028）：符合 CWE-22（路径穿越）。漏洞位于可交付代码 028.php:7，外部输入来自查询参数 page，source→sink 链在静态层面闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权目标并手动运行；禁止对生产环境使用。原始 poc.sh 中的 curl 命令仅作参考，不得通过管道自动执行。

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
| safety_guard | 安全防护 | 2.54 | 是 |
| surface_mapper | 攻击面测绘 | 7.83 | 是 |
| deep_finder | LLM 深挖 | 3.57 | 是 |
| candidate_screener | 候选筛选 | 2.96 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.11 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 3.95 | 是 |
| coordinator | 管线协调 | 4.57 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
