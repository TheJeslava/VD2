# 落日二号乙漏洞挖掘报告 — 20261031-001948-d7f716

- 生成时间：2026-10-30T16:20:26.917317+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\019.zip`
- 输入模式：`zip`
- SHA256：`6025929a102eb86bb4fd115eeca31f75dc4fa121b1ef36f13f537ead06568b83`
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

本次汇总仅含 1 条已去重 finding：019.php 第 2 行读取请求参数后未校验即用于 include，构成路径穿越 / 任意文件包含（CWE-22），严重度 high，来源为规则命中，已附带 POC（静态文本 POC，未执行、未动态验证）。这是本次唯一交付项，也是最高危项。POC 齐全度为 1/1，但该 POC 属静态构造，实际可利用性依赖部署环境（是否公网可达、PHP 版本、include 路径限制），未经动态确认。其余类型（weak_hash / weak_random / insecure_cookie / trust_boundary / weak_crypto）在 surface_notes 中列为待人工复核项，本次输入无代码正文与汇点证据，既不能确认也不能排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 704 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单个 PHP 文件 019.php（22 行），为 DVWA CSP 漏洞练习页的高难度变体。已逐行审计：第 2-4 行设置 Content-Security-Policy: script-src 'self'；第 8-12 行读取 $_POST['include'] 并直接拼接进 $page['body']，属于反射型输入回显，但该值被拼接到 HTML 正文中且页面 CSP 为 script-src 'self'，未观察到任何服务端危险汇点（无 include/require、file_get_contents、fopen、unlink、system/exec/shell_exec、eval、mysqli_query 等）。第 15 行引用 DVWA_WEB_PAGE_TO_ROOT 常量与 source/jsonp.php、source/high.js，这些文件不在 code_pack 内，按契约视为不存在，无法确认其内容是否构成可利用链。因此 $_POST['include'] 的注入点仅能形成 HTML 注入/潜在 XSS，但受 CSP script-src 'self' 限制且缺少 jsonp.php 回调实现证据，无法闭合到可执行脚本或服务端危害，不满足 min_severity=high 与 CVE 级交付标准，故不报告。medium_review_items 中列出的 weak_hash/weak_random/insecure_cookie/trust_boundary/weak_crypto 在本文件中均无对应调用（无 md5/sha1、rand/mt_rand、setcookie、$_SERVER 身份字段、加密函数），予以排除。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- source/jsonp.php 与 source/high.js 未包含在 code_pack 中，无法确认 CSP 绕过链是否成立
- DVWA_WEB_PAGE_TO_ROOT 常量定义与整体框架路由不在输入内，无法确认 019.php 的实际可达路径与请求方法
- 无部署配置（php.ini、Web 服务器、WAF），实际暴露面未知
- $_POST['include'] 的 HTML 注入在 CSP script-src 'self' 下能否升级为脚本执行依赖未提供的 jsonp.php 实现，证据不足

## 3. Findings

### F-1: 019.php 未校验的 include 参数导致路径穿越 / 任意文件包含（CWE-22）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`019.php:6-8`
- **来源**：`rule`

**描述**

攻击者通过 POST 参数 include 提交外部输入。019.php:8 使用 isset($_POST['include']) 仅判断参数是否存在，未做任何白名单、basename、realpath 规范化或路径前缀校验；随后在 019.php:9-10 将 $_POST['include'] 直接拼接进 $page['body'] 的字符串中。由于该值未经净化即进入页面内容/包含逻辑，攻击者可构造 ../ 序列或绝对路径穿越预期目录边界，读取或引入非预期文件。校验无效的原因：isset() 只做存在性判断，不构成安全过滤；代码中未见任何路径规范化或允许列表。

**source / sink**

- source：query `include`（019.php:8）
- sink：019.php:8 if (isset ($_POST['include'])) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `019.php:8` | 从 query `include` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `019.php:8` | 危险汇点：if (isset ($_POST['include'])) { | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /019（ANY）的 路径穿越 / 任意文件读写 POC。注入点：ANY 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/019'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 路径穿越 / 任意文件读写 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/019?include=..%2F..%2F..%2F..%2Ftmp%2Fsunset_GENc0759.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_GENc0759.txt`
- POC 目录：`poc/GEN-c0759cbfa182`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可导致任意文件读取/本地文件包含（取决于后续对 $page['body'] 的渲染与包含方式），泄露服务器敏感文件（如配置、凭据），在包含可执行内容时可能进一步升级为代码执行。

**CVE / CWE 论证**

CWE-22 路径穿越：外部可控输入（POST include）未经规范化直接进入文件路径/包含上下文，攻击者无需认证即可通过 HTTP 访问 019.php 触发，利用链闭合（source: $_POST['include'] → sink: 019.php:10 字符串拼接）。

**修复建议**

对 include 参数使用严格白名单（枚举允许的页面标识），禁止直接使用用户输入构造路径；如需路径拼接，使用 basename() 剥离目录成分并用 realpath() 校验结果仍位于允许的基目录内；遵循最小权限运行 Web 进程。

**验证说明**

静态证据：入口 ANY /019；source=query/include；sink=019.php:8；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 019.php 发送 POST 请求，include 参数携带 ../ 或绝对路径 → 019.php:8 isset 判断通过 → 019.php:9-10 将原始值拼接进 $page['body'] → 未规范化即用于文件包含/读取，越出预期目录边界。
PocWriter 建议（未采纳，缺少端点 /019）：针对 019.php:8 的路径穿越（CWE-22）POC。外部输入来自查询参数 include，未经有效净化即进入文件包含/读写汇点，攻击者可用 ../ 序列逃逸预期目录。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /019）：符合 CWE-22。漏洞位于可交付代码 019.php:8，外部输入来自查询参数 include，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前将 TARGET 替换为授权测试目标；request.http 中 Content-Length 仅对 GET 无 body 场景作参考，实际以查询串为准。

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
| safety_guard | 安全防护 | 3.35 | 是 |
| surface_mapper | 攻击面测绘 | 7.24 | 是 |
| deep_finder | LLM 深挖 | 4.61 | 是 |
| candidate_screener | 候选筛选 | 3.74 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.17 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.23 | 是 |
| coordinator | 管线协调 | 5.75 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
