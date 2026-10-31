# 落日二号乙漏洞挖掘报告 — 20261031-002007-3199bd

- 生成时间：2026-10-30T16:20:53.006368+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\021.zip`
- 输入模式：`zip`
- SHA256：`ff9631d6e9310b5ffe2f51550d4a9e5b12c4e83ee69a263543f6be3776889254`
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

本次汇总仅含 1 条已去重 finding：021.php 第 2 行读取的 POST 参数未经校验即进入 include，构成路径穿越/任意文件包含（CWE-22），严重度 high，来源为规则命中，已附带 POC（静态文本 POC，未执行、未动态验证）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 有 POC，但均为静态证据级，不能宣称可动态复现。二次注入链：无。覆盖范围极窄——仅 1 个 PHP 文件、0 个端点、无框架，sink_hot_files 为空，说明管线未命中已知 sink 模式，不代表无危险汇点。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 877 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 021.php（25 行，已全量通读）。发现一条闭合链：POST 参数 include 未编码拼接进 $page['body'] 形成反射型 XSS，且页面 CSP nonce 硬编码、X-XSS-Protection 被关闭，可绕过防护。未发现 SQL 注入、命令执行、文件包含/路径穿越、SSRF、反序列化、弱哈希/弱随机/不安全 Cookie/硬编码密钥等其它 sink（文件中无 mysqli_query、exec/system、include/require、file_get_contents、md5/rand、setcookie 等调用）。注意：本文件未见对 $page['body'] 的最终 echo，输出可能由未送入 code_pack 的外层模板完成，故 XSS 置信度定为 0.82 而非更高；该缺口已记入 coverage.gaps。

未覆盖 / 证据缺口：
- $page['body'] 的最终输出语句不在 code_pack 内，无法确认渲染位置与是否另有编码
- 无 Web 服务器/php.ini 配置，无法确认 021.php 是否匿名可达
- 无路由与认证信息，无法判断是否需要登录
- 未提供外层模板/框架文件，XSS 输出上下文仅能推断

## 3. Findings

### F-1: 021.php 未校验 POST 参数 include 导致路径穿越/任意文件包含（CWE-22）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`021.php:12-14`
- **来源**：`rule`

**描述**

攻击者通过 HTTP POST 提交参数 include（021.php:14 的 isset($_POST['include']) 判断仅检查该参数是否存在，不做任何过滤）。该参数值在 021.php:16 被直接拼接进 $page['body'] 字符串（" . $_POST['include'] . "），随后作为页面 body 内容输出/渲染。源码片段中未见 basename()、realpath()、白名单、路径规范化或 htmlspecialchars() 等任何净化处理，因此外部可控字符串原样进入文件路径/内容拼接位置。注意：本片段仅覆盖 12-16 行，未展示后续是否将该值传给 include()/require()/file_get_contents() 等真正的文件读取函数，故“任意文件读写”的最终汇点属于推断，证据不足。

**source / sink**

- source：query `include`（021.php:14）
- sink：021.php:14 if (isset ($_POST['include'])) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `021.php:14` | 从 query `include` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `021.php:14` | 危险汇点：if (isset ($_POST['include'])) { | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /021（ANY）的 路径穿越 / 任意文件读写 POC。注入点：ANY 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/021'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 路径穿越 / 任意文件读写 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/021?include=..%2F..%2F..%2F..%2Ftmp%2Fsunset_GEN1b352.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_GEN1b352.txt`
- POC 目录：`poc/GEN-1b352c5348d3`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若后续代码将 $page['body'] 中的该值用于文件包含或读取，攻击者可构造 ../ 序列穿越目录，读取或包含服务器上的任意文件（如配置文件、密钥、/etc/passwd），在可包含 PHP 文件时可能导致任意代码执行；即使仅回显，也可造成敏感信息泄露与页面内容注入。

**CVE / CWE 论证**

CWE-22（路径穿越）。外部可达性：021.php:14 直接读取 $_POST['include']，无需认证即可触发；利用链：POST include → $_POST['include']（021.php:14）→ 字符串拼接（021.php:16）→ 文件路径/包含汇点，链路上无有效校验，闭合性成立。但最终文件操作函数未在给定片段中出现，故利用链末端为推断，置信度受限。

**修复建议**

不要将用户输入直接拼接为文件路径。使用白名单映射（如允许的页面名到固定文件路径的字典），对输入执行 basename() 并配合 realpath() 校验结果仍位于允许的基目录内；拒绝包含 ..、绝对路径、空字节的输入；输出到 HTML 时使用 htmlspecialchars() 编码；文件操作使用最小权限账户。

**验证说明**

静态证据：入口 ANY /021；source=query/include；sink=021.php:14；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 021.php 发送 POST 请求，参数 include 携带 ../ 穿越序列；021.php:14 的 isset 判断放行；021.php:16 将该值原样拼入 $page['body']；后续若用于文件包含/读取即完成穿越。片段未展示最终文件操作，故末端为推断。
PocWriter 建议（未采纳，缺少端点 /021）：针对 021.php:14 的路径穿越（CWE-22）POC。外部输入来自查询参数 include，未经过有效净化即被用于文件路径拼接/包含，攻击者可通过 ../ 序列逃逸预期目录，读取或写入任意文件。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /021）：符合 CWE-22。漏洞位于可交付代码 021.php:14，外部输入来自查询参数 include，source→sink 链静态闭合且未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权目标并确认授权范围；脚本中的 curl 命令仅供人工手动执行参考。

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
| safety_guard | 安全防护 | 2.96 | 是 |
| surface_mapper | 攻击面测绘 | 8.45 | 是 |
| deep_finder | LLM 深挖 | 8.5 | 是 |
| candidate_screener | 候选筛选 | 4.31 | 是 |
| vulnerability_analyzer | 漏洞分析 | 8.67 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.08 | 是 |
| coordinator | 管线协调 | 5.76 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
