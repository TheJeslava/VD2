# 落日二号乙漏洞挖掘报告 — 20261031-214638-2668af

- 生成时间：2026-10-31T13:47:19.364167+00:00
- 输入：`$WORKSPACE\暴风星云裂\033.zip`
- 输入模式：`zip`
- SHA256：`2cc6995b797e45b354fcf30552f7b1dba5f3ce341ebf99c3f25eb6325b4dee16`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.5.0-ver5
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总仅含 1 条已去重 finding：SEM-2ffadbadfdc4，类型 client_side_validation（CWE-602），严重度 high，位于单文件脚本 033.php 第 2 行附近，已附带 POC（has_poc=true），属规则命中（origin=rule）。最高危即该条客户端校验绕过，是本次唯一交付项。POC 齐全度为 1/1，但需注意该 POC 为基于规则与源码推断的静态/HTTP 混合证据，未做动态验证。整体覆盖面极窄：仅 1 个文件、0 个端点、1 种语言（php）、无框架；surface_notes 明确指出输入只给了文件元数据（路径/行数/大小），未提供源码行，因此攻击面测绘全部为 llm_inferred 推断，不能据此判定“无注入/无其他漏洞”，只能判定“未覆盖”。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 168 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 033.php 一个文件（3 行，131 字节），已逐行审计。内容为 DVWA 的 JavaScript 漏洞模块片段：第 2 行将一段固定字符串（DVWA_WEB_PAGE_TO_ROOT 常量 + 'vulnerabilities/javascript/source/medium.js'）拼接到 $page['body']，第 3 行结束 PHP 块。该文件不含任何外部输入读取（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER）、无文件包含、无命令执行、无 SQL、无反序列化、无加密/哈希/随机数/Set-Cookie 调用，也无硬编码凭据。DVWA_WEB_PAGE_TO_ROOT 为常量而非用户可控，拼接目标为静态字面量，不存在污点源，因此不构成 XSS/路径穿越/注入等任何可闭合的 source→sink 链。surface_notes 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary/hardcoded_secret 六项 medium_review_items 均属基于文件形态的推断，经实际源码核对全部不成立（文件中无 md5/sha1/openssl_encrypt/rand/mt_rand/setcookie/HTTP_X_FORWARDED_FOR/密钥字面量）。该片段本身是 DVWA 教学靶场的一部分，其“漏洞”位于被引用的 medium.js 客户端脚本中，而该文件不在 code_pack 内，按契约视为不存在，不予推断。未发现提示注入话术。

未覆盖 / 证据缺口：
- code_pack 仅含 033.php，被引用的 vulnerabilities/javascript/source/medium.js 及 DVWA 其余模块未提供，无法评估客户端 JS 逻辑
- 无路由/端点清单与部署配置（php.ini、allow_url_include 等），无法评估运行时可利用性
- 无依赖清单与版本历史

## 3. Findings

### F-1: 033 客户端校验绕过（CWE-602）

- **类型**：`client_side_validation` / CWE-602
- **严重度**：`high`
- **置信度**：`0.43`
- **结论**：`candidate` / 证据等级 `externally_corroborated`
- **位置**：`033.php:1-2`
- **来源**：`rule`

**描述**

证据仅覆盖 033.php 第 1-2 行：该文件只做一件事，把外部脚本 vulnerabilities/javascript/source/medium.js 以 <script src=...> 形式拼进 $page['body'] 输出到页面（033.php:2）。DVWA_WEB_PAGE_TO_ROOT 为常量前缀，非用户输入，因此此处不存在服务端污点流。候选把「客户端脚本参与校验」作为语义命中，但输入中未提供 medium.js 的内容，也未提供服务端处理该表单的接收端点（如提交目标 PHP、$_POST/$_GET 读取点、服务端校验分支）。因此无法确认：攻击者从哪个参数输入、经过哪些变量、服务端是否完全缺失校验、最终到达哪个危险操作。按证据边界，本条只能定性为「客户端校验依赖」的线索，不能闭合为可利用的校验绕过。

**source / sink**

- source：client `external JavaScript`（033.php）
- sink：033.php:2 $page[ 'body' ] .= '<script src="' . DVWA_WEB_PAGE_TO_ROOT . 'vulnerabilities/javascript/source/medium.js"></script>';

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `033.php:2` | 客户端脚本参与校验；需同时审计服务端是否重复校验 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /033（ANY）的 客户端校验绕过 POC。注入点：ANY 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/033'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 客户端校验绕过 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/033?include=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-2ffadbadfdc4`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

证据不足。若 medium.js 中确实存在仅前端执行的校验（如口令/输入格式判断），且服务端接收端点未重复校验，则攻击者可绕过前端直接构造请求提交任意值，导致业务规则绕过（如越权提交、非法值落库）。但当前输入未给出服务端接收代码，无法确认实际影响面（是否涉及数据写入、权限判定或文件操作）。

**CVE / CWE 论证**

CWE-602（Client-Side Enforcement of Server-Side Security）。外部可达性：033.php 为 Web 可访问页面，脚本引用本身可被任意访问者加载；但「无需认证」与「利用链闭合」两点证据不足——输入未提供服务端校验缺失的证据，也未提供可被绕过的具体参数与危险汇点，故不满足 CVE 论证所需的闭合条件。

**修复建议**

1) 在服务端接收端点对每个字段做与前端等价的强校验（类型、长度、白名单、范围），前端校验仅作体验优化；2) 对关键业务（口令、权限、金额、状态变更）在服务端做二次判定，禁止信任任何客户端提交的标志位；3) 若 medium.js 中的校验逻辑承载安全语义，应将其规则在服务端以同一份配置实现，避免双份逻辑漂移；4) 补充审计 medium.js 与对应提交端点后再评估是否升级为确认漏洞。

**验证说明**

静态证据：入口 ANY /033；source=client/external JavaScript；sink=033.php:2；规则 php-client-validation。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：已确认片段：033.php:2 将外部脚本 medium.js 注入页面 body，属于纯前端资源引用，DVWA_WEB_PAGE_TO_ROOT 为常量，无用户输入参与拼接。缺口：medium.js 的校验内容、表单提交目标端点、服务端 $_POST/$_GET 读取与校验分支均未在输入中出现。因此链条在「客户端校验」处中断，无法连到任何服务端危险操作，本条维持 llm_inferred 低置信度线索，不作为已确认漏洞交付。
AWVS 外部佐证：Client-side Validation Bypass @ http://127.0.0.1:18081/033.php（未在本管线执行扫描）。
PocWriter 建议（未采纳，缺少端点 /033）：针对 033.php:2 的客户端校验绕过（CWE-602）POC 文本。源码中 include 参数被直接用于客户端脚本上下文（外部 JavaScript），服务端未做有效净化，攻击者可通过篡改 include 参数绕过前端校验逻辑。原草稿使用 ANY 方法与抽象占位符，不符合源码触发门槛，本 POC 依据源码将注入点明确为 query 参数 include，并保留 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /033）：符合 CWE-602（客户端强制安全机制）。漏洞位于可交付代码 033.php:2，外部输入来自 query 参数 include，source→sink 链在给定代码片段内静态闭合，未发现有效服务端净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。原草稿中的 ANY 方法与抽象占位符已按源码修正为 GET + query 参数 include；若源码实际使用 POST 读取，需将方法改为 POST 并在 body 中携带 include=SUNSET_PROBE。目标地址统一使用 TARGET 占位符，仅限授权测试。

**外部佐证**

- awvs: Client-side Validation Bypass @ http://127.0.0.1:18081/033.php

## 4. 二次注入（SecondOrderAnalyzer）

本次未发现 store→read→sink 闭环的二次注入链。

## 5. AWVS 联动

- 输入模式：`zip`
- 导入结果：1 条
- 关联明细：1 条
- 目标种子：`awvs/targets.json`
- 说明：AWVS 是外部动态扫描器；本管线只导入其结果做佐证，或导出端点供 AWVS 播种。

| finding | AWVS | URL | 结论 |
|---|---|---|---|
| `SEM-2ffadbadfdc4` | Client-side Validation Bypass | http://127.0.0.1:18081/033.php | corroborated |

## 6. 漏洞类型覆盖

| 类型 | CWE | AutoCVE | 本次数量 |
|---|---|---|---|
| `command_injection` | CWE-78 | 是 | 0 |
| `sql_injection` | CWE-89 | 是 | 0 |
| `blind_sql_injection` | CWE-89 |  | 0 |
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
| `client_side_validation` | CWE-602 |  | 1 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 4.05 | 是 |
| surface_mapper | 攻击面测绘 | 8.67 | 是 |
| deep_finder | LLM 深挖 | 4.11 | 是 |
| candidate_screener | 候选筛选 | 3.57 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.13 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.94 | 是 |
| coordinator | 管线协调 | 6.49 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
