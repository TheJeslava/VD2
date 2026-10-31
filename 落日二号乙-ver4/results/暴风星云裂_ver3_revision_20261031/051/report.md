# 落日二号乙漏洞挖掘报告 — 20261031-012243-88b4ab

- 生成时间：2026-10-30T17:23:16.334655+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\051.zip`
- 输入模式：`zip`
- SHA256：`96483940cd4d3e7d3eebe8443bc19f27aedea70513cee1c5302276aeb59557a9`
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

本次汇总仅含 1 条已去重 finding：051.php 的开放重定向候选（GEN-6e4cfba5fa5e，medium，CWE-601），但该条自身描述为「header 重定向目标为固定字符串，污点未到达汇点」，即规则命中而数据流未闭合，属弱证据候选，需人工确认是否成立。最高危即此条 medium，无 high/critical。POC 齐全度：1/1 条带 POC，但该 POC 为静态证据型（基于源码固定字符串重定向），不具备动态可复现性，不能宣称可动态验证。整体样本极小（单文件 051.php，14 行，289 字节，php:1，无框架、无路由、无端点清单），攻击面测绘指出 051.php:3 为唯一已知污点源，但 sink_hot_files 为空，注入类（command_injection / sql_injection / path_traversal / xss）均未被规则命中，属未覆盖而非已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 383 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 051.php 全部 14 行。第 4-5 行从 $_GET['default'] 读取外部输入到 $default，第 8 行用 stripos($default, "<script") 做黑名单检查，命中则第 9 行 header 跳转并 exit。关键缺口：该文件在第 14 行 ?> 结束，$default 在读取与校验之后没有任何输出（echo/print）、文件操作（include/require/fopen/file_get_contents）、SQL 或命令执行汇点，因此 source→sink 链不闭合，无法构造可利用 POC。虽然黑名单仅拦截 "<script"（可被 <img onerror>、<svg onload>、大小写/编码变体绕过），但缺少输出点使反射型 XSS 无法成立；同理不存在文件包含、路径穿越、SQL 注入、命令注入的可达汇点。surface_notes 中关于 include/文件操作/XSS 的假设均未在代码中得到证实。未发现满足 CVE 级别且链闭合的漏洞，按“宁可漏报不可误报”原则返回空数组。

未覆盖 / 证据缺口：
- 051.php 仅 14 行且无任何 sink，$default 读取后未被使用；若真实部署中该变量在 code_pack 之外的文件被引用，则需补充代码才能评估
- 缺少 php.ini / Web 服务器配置，无法评估文件包含类风险（当前代码也无 include）
- 无端点清单，无法确认脚本对外暴露路径与认证要求
- code_pack 之外文件按规则视为不存在，未覆盖

## 3. Findings

### F-1: 051.php 开放重定向候选（CWE-601）：header 重定向目标为固定字符串，污点未到达汇点

- **类型**：`open_redirect` / CWE-601
- **严重度**：`medium`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`051.php:7-9`
- **来源**：`rule`

**描述**

证据显示 051.php:5 从 query 参数 `default` 读取外部输入，051.php:7-9 的代码为：先注释「Do not allow script tags」，再用 `stripos($default, "<script") !== false` 判断输入是否包含 `<script`，命中时执行 `header("location: ?default=English")`。关键事实是：该 header 的 Location 值是硬编码字符串 `?default=English`，其中不含变量 `$default`，因此外部输入并未进入重定向目标。攻击者可控的 `default` 只影响「是否触发该分支」这一布尔判断，无法改变跳转目的地，也无法注入 CRLF（值中无用户数据）。因此候选 exploit_chain 第 2 步所称「污点进入 open_redirect 汇点」与给出的代码片段不符：片段中不存在把 `$default` 拼进 Location 的语句。按当前 code_pack 可见范围，该候选不构成开放重定向；若 051.php 其他行（未在片段中给出）存在 `header("location: " . $default)` 之类的拼接，则需另行取证，本片段不足以支撑。

**source / sink**

- source：query `default`（051.php:5）
- sink：051.php:9 header ("location: ?default=English");

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `051.php:5` | 从 query `default` 读取外部输入 | 污点进入 default |  |
| 2 | `051.php:9` | 危险汇点：header ("location: ?default=English"); | 污点进入 open_redirect 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /051（ANY）的 开放重定向 POC。注入点：ANY 参数 default；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/051'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 开放重定向 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/051?default=%2F%2Fexample.com'
```
预期：响应 30x 且 Location 指向攻击者控制的域名。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`//example.com`
- POC 目录：`poc/GEN-6e4cfba5fa5e`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

按现有证据：无开放重定向影响。若强行按候选结论推断，最坏情形也仅是把用户重定向到站内固定地址 `?default=English`，不构成跨站跳转、不泄露凭据、不导致钓鱼落地页劫持。当前证据下影响为「无」（证据不足支撑 CWE-601 的实际影响）。

**CVE / CWE 论证**

不满足 CWE-601 的构成要件：开放重定向要求攻击者可控数据进入 Location/Refresh 等跳转目标。此处 Location 为常量 `?default=English`，`$default` 仅参与 `stripos` 判断，未参与响应头构造，污点链在 051.php:8 处被「仅用于比较」切断，未闭合到 051.php:9 的 header 值。外部可达性成立（query 参数无需认证即可访问），但可达不等于可利用；利用链不闭合，故不应授予 CVE/CWE-601 归类。

**修复建议**

1) 若后续确认存在动态跳转，应改为白名单映射：仅接受预定义键（如 `en`/`zh`），用映射表取固定 URL，禁止直接把参数拼入 Location；2) 对跳转目标做规范化与同源校验（解析后校验 scheme/host 属于本站），拒绝 `//evil.com`、`https://`、`\\`、含 CR/LF 的值；3) 输出前过滤 `\r\n` 防响应头注入；4) 当前代码建议保留 `<script` 检查的同时，明确注释该 header 为固定回退值，避免审计误判；5) 若确无动态跳转需求，可关闭该候选。

**验证说明**

静态证据：入口 ANY /051；source=query/default；sink=051.php:9；规则 php-redirect。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `051.php?default=<payload>` → 051.php:5 将参数读入 `$default` → 051.php:8 用 `stripos($default, "<script")` 做包含判断 → 命中时 051.php:9 执行 `header("location: ?default=English")`。由于 Location 值为常量，`$default` 的内容不会出现在响应头中，链条在「比较」处终止，未到达可控跳转汇点，故不构成开放重定向。
PocWriter 建议（未采纳，缺少端点 /051）：针对 051.php:9 的开放重定向（CWE-601）POC。外部输入来自查询参数 `default`，被直接用于重定向目标（sink 位于 051.php 第 9 行），未发现有效净化，可导致跳转到攻击者控制的域名。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /051）：符合 CWE-601（URL 重定向到不可信站点）。漏洞位于可交付代码 051.php 第 9 行，外部输入来自查询参数 `default`，source→sink 链在给定代码范围内静态闭合，未发现有效净化（如白名单校验或相对路径强制），具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权测试实例地址，并确认已获授权。原始确定性请求结构 `curl -sS -i -X ANY 'http://TARGET:8080/051?default=%2F%2Fexample.com'` 予以保留；`-X ANY` 表示方法不限，实际测试可用 GET。禁止对非授权目标使用。

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
| `open_redirect` | CWE-601 |  | 1 |
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
| safety_guard | 安全防护 | 2.07 | 是 |
| surface_mapper | 攻击面测绘 | 6.9 | 是 |
| deep_finder | LLM 深挖 | 3.33 | 是 |
| candidate_screener | 候选筛选 | 2.24 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.12 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.55 | 是 |
| coordinator | 管线协调 | 5.98 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
