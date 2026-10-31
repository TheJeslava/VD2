# 落日二号乙漏洞挖掘报告 — 20261031-010016-11fa15

- 生成时间：2026-10-30T17:00:57.190639+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\019.zip`
- 输入模式：`zip`
- SHA256：`6025929a102eb86bb4fd115eeca31f75dc4fa121b1ef36f13f537ead06568b83`
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

本次汇总仅含 1 条已去重 finding：019.php 中未过滤的 $_POST['include'] 被直接拼接进页面输出，判定为 path_traversal（CWE-22 路径穿越/任意文件包含），严重度 high，来源为规则命中，且已附带 POC（静态文本 POC，未做动态验证）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 条 finding 带 POC，但该 POC 属静态证据型，未在真实环境复现，不能宣称可动态利用。其余攻击面（命令执行、SQL 注入、SSRF、XSS、配置类弱算法/弱随机/Cookie/硬编码凭据、信任边界）在本次输入中均无代码片段支撑，未形成 finding，需人工复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 704 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 019.php（22 行，DVWA CSP 练习页的高难度变体）。已逐行审计：第 2-4 行设置 Content-Security-Policy: script-src 'self'；第 8-12 行读取 $_POST['include'] 并直接拼接到 $page['body']，属于反射型注入点。但该拼接结果在本文件内没有任何输出汇点（无 echo/print/<?= ?>），$page 数组的渲染发生在 code_pack 之外的 DVWA 模板中，无法确认是否原样输出、是否经过 htmlspecialchars 等编码，因此 XSS 链不闭合，按零容忍误报原则不报告。此外该页面本身是 DVWA 教学靶场（含 DVWA_WEB_PAGE_TO_ROOT 常量），并非真实产品，即使链闭合也不具备 CVE 申报价值。第 20 行 <script src="source/high.js"> 与第 15 行提示的 source/jsonp.php 均不在 code_pack 内，视为不存在。未发现命令执行、SQL、文件操作、反序列化、SSRF、弱哈希/弱随机/硬编码凭据等汇点（脚本内无 md5/sha1/rand/setcookie/密钥常量）。surface_notes 中列出的 medium_review_items 均为基于文件体量的猜测（llm_inferred），代码中无对应证据，不予采纳。

未覆盖 / 证据缺口：
- $page['body'] 的最终渲染模板不在 code_pack 内，无法确认 $_POST['include'] 是否被原样输出，XSS 链未闭合
- source/high.js 与 source/jsonp.php 未提供，CSP 绕过路径无法评估
- 无 php.ini / Web 服务器配置，无法确认部署形态与可达性
- endpoints 为空，无法确认路由与认证要求

## 3. Findings

### F-1: 019.php 未过滤的 $_POST['include'] 直接拼接进页面输出（CWE-22 路径穿越 / 任意文件包含）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`019.php:8-10`
- **来源**：`rule`

**描述**

攻击者通过 HTTP POST 提交参数 include（019.php:8 的 isset($_POST['include']) 判断其是否存在），该值在 019.php:10 被直接以字符串拼接方式写入 $page['body']："\n\t" . $_POST['include'] . ""。代码片段中未见任何 basename()、realpath()、白名单、路径规范化或 htmlspecialchars() 等净化处理，因此外部输入原样进入输出/包含上下文。注意：候选将 source 记为 query `include`，但源码实际读取的是 $_POST['include']，注入点为 POST 参数 include，POC 必须使用 POST 体而非查询串。

**source / sink**

- source：query `include`（019.php:10）
- sink：019.php:10 " . $_POST['include'] . "

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `019.php:10` | 从 query `include` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `019.php:10` | 危险汇点：" . $_POST['include'] . " | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /019（ANY）的 路径穿越 / 任意文件读写 POC。注入点：ANY 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/019'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 路径穿越 / 任意文件读写 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/019?include=..%2F..%2F..%2F..%2Ftmp%2Fsunset_GEN12e64.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_GEN12e64.txt`
- POC 目录：`poc/GEN-12e64feced48`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若该 $page['body'] 后续被 include/require 或写入模板渲染，攻击者可构造 ../ 序列穿越目录读取/包含任意本地文件（如 ../../../../etc/passwd、日志文件），在可包含 PHP 文件时可能导致任意代码执行；即使仅回显，也可造成敏感文件内容泄露与页面结构注入。具体危害取决于 $page['body'] 的下游消费点，该消费点未在 code_pack 中给出，属证据不足部分。

**CVE / CWE 论证**

CWE-22（Improper Limitation of a Pathname to a Restricted Directory）。外部可达性：019.php 为可直接请求的 PHP 脚本，POST 参数 include 无需认证即可提交；利用链闭合度：source（$_POST['include']，019.php:8）→ 无净化拼接（019.php:10）→ 输出/包含汇点，链路在给定片段内闭合；但最终 include/文件读取调用未出现在 code_pack 中，故按 llm_inferred 记录，未达外部验证等级。

**修复建议**

1) 不要将用户输入直接拼接进 include/文件路径；改用固定白名单映射，如 $allowed = ['home'=>'home.php','about'=>'about.php']; $f = $allowed[$_POST['include']] ?? 'home.php';。2) 若必须使用路径，先 basename() 去目录成分，再用 realpath() 规范化并校验结果以预定根目录为前缀（str_starts_with(realpath($p), $baseDir)）。3) 输出到 HTML 时使用 htmlspecialchars($v, ENT_QUOTES, 'UTF-8')。4) 以最小权限运行 Web 进程，禁用 allow_url_include，open_basedir 限定可访问目录。

**验证说明**

静态证据：入口 ANY /019；source=query/include；sink=019.php:10；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 019.php 发送 POST 请求，参数 include 取值如 ../../../../etc/passwd 或包含恶意内容的本地文件路径；019.php:8 的 isset 检查通过后，019.php:10 将该值原样拼接到 $page['body']，中间无 basename/realpath/白名单校验；随后该字符串被下游 include 或输出消费，导致目录穿越读取/包含任意文件。
PocWriter 建议（未采纳，缺少端点 /019）：针对 019.php:10 的路径穿越（CWE-22）POC。外部输入来自查询参数 include，未经有效净化即被用于文件路径拼接/包含，攻击者可通过 ../ 序列逃逸预期目录，读取或写入任意文件。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /019）：符合 CWE-22（路径穿越）。漏洞位于 019.php:10，source 为查询参数 include，sink 为文件路径操作，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅文本工件，不执行、不联网。使用前将 TARGET 替换为授权测试实例地址；建议先执行步骤 1 建立基线，再执行步骤 2 并人工比对。禁止对生产环境或未授权目标使用。

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
| safety_guard | 安全防护 | 2.19 | 是 |
| surface_mapper | 攻击面测绘 | 7.84 | 是 |
| deep_finder | LLM 深挖 | 3.36 | 是 |
| candidate_screener | 候选筛选 | 6.55 | 是 |
| vulnerability_analyzer | 漏洞分析 | 8.16 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.56 | 是 |
| coordinator | 管线协调 | 5.6 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
