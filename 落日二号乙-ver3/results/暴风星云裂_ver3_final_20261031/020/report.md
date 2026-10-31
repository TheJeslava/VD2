# 落日二号乙漏洞挖掘报告 — 20261031-013936-7ed841

- 生成时间：2026-10-30T17:40:23.355454+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\020.zip`
- 输入模式：`zip`
- SHA256：`f7bc24fccdcc53d2a999c3468bedf97d91c239734baf4f227ae7ef495dbe0b26`
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

本次汇总基于已去重的 2 条 findings，均集中在单文件 PHP 脚本 020.php：一条为反射型 XSS（LLM-370901c0cb4c，medium，020.php 第 17 行附近，POST 参数 include 未经编码直接输出 script 标签），一条为 CSP 配置缺陷（SEM-582e93de1b73，medium，020.php 第 3 行，script-src 白名单过宽，CWE-693），两者互为放大关系——CSP 过宽使 XSS 可加载外部恶意脚本。最高危为上述 XSS 与 CSP 的组合，但严重度均为 medium，无 high/critical。两条 finding 均标记 has_poc=true，POC 齐全（均为 HTTP 类 POC，目标以 TARGET 占位，仅限授权测试）。需注意：本次输入未提供 020.php 代码正文，仅有文件元数据与热点行号，findings 的行级证据来自上游发现阶段，本汇总不新增漏洞、不做动态验证。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1199 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 020.php（27 行）。已逐行审计：第 3-5 行设置 CSP，第 13-17 行读取 $_POST['include'] 并直接拼接进 <script src='...'>，构成反射型 XSS，且 CSP 白名单包含 pastebin/hastebin/unpkg/jsdelivr/digi.ninja 等可公开托管脚本的域，使 CSP 无法阻止利用，故报告该 finding。未发现 SQL 拼接、命令执行、文件包含/路径拼接、反序列化等 sink；文件中无 md5/sha1、无加密调用、无 rand 令牌、无 setcookie，故 weak_hash/weak_crypto/weak_random/insecure_cookie 均无证据。输入中未出现诱导性指令，未记录 prompt_injection。未覆盖范围：无 composer.json、无 Web 服务器配置、无路由与部署信息，无法确认访问路径、认证保护与错误显示配置；这些缺口影响可利用性评估但不影响 XSS 链本身的闭合性。

未覆盖 / 证据缺口：
- 无 HTTP 端点清单与路由，无法确认 020.php 实际访问路径与请求方法
- 无 Web 服务器/php.ini 配置，无法确认 CSP 是否被覆盖或错误显示设置
- 无部署上下文（是否位于认证网关/WAF 之后），影响暴露程度评估
- 无依赖清单，无法评估第三方组件 CVE

## 3. Findings

### F-1: 020.php 通过 POST 参数 include 反射注入 script 标签（CSP 白名单过宽导致可加载外部恶意脚本）

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.87`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`020.php:13-17`
- **来源**：`llm_finding`

**描述**

脚本在第 13-17 行读取 $_POST['include']，未经任何 HTML 属性编码或 URL 白名单校验，直接拼接进 <script src='...'> 的 src 属性并输出到响应体。攻击者可构造 include 值闭合单引号并注入任意 HTML/JS（如 '></script><script>alert(document.domain)</script>），或直接指向 CSP 白名单内的可控托管（pastebin.com、hastebin.com、unpkg.com、cdn.jsdelivr.net、digi.ninja 等）加载外部脚本。第 3-5 行设置的 CSP 明确把上述第三方域列入 script-src，等于为攻击者提供了合法的脚本加载源，使 CSP 无法阻止利用。由于是 POST 反射，需诱导受害者提交表单或由攻击者构造自动提交页面，属于反射型 XSS。

**source / sink**

- source：body `include`（020.php）
- sink：020.php:17 字符串拼接进 <script src='...'> 并输出到 HTML 响应（第 14-16 行 $page['body'] .= ...）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `020.php:13` | 检测到 POST 参数 include 存在 | 原始攻击者字符串 | 无任何输入校验 |
| 2 | `020.php:14-16` | 将 include 值直接拼接到 <script src='...'> 标签中 | 未编码，单引号可闭合属性 |  |
| 3 | `020.php:18-27` | $page['body'] 最终输出到响应页面（脚本后续渲染 body） | 注入的 HTML/JS 进入响应体 |  |

**POC**

针对 /020.php（POST）的反射型跨站脚本 POC。注入点为 POST 表单参数 include，该参数值被直接输出到响应页面而未做 HTML 编码，导致脚本在受害者浏览器执行。目标地址统一使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/020.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/020.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'include=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-370901c0cb4c`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

在受害者浏览器上下文执行任意 JavaScript，可窃取会话 Cookie、伪造请求、篡改页面内容；CSP 因白名单过宽无法提供有效防护。

**CVE / CWE 论证**

CWE-79 反射型 XSS。外部无需认证即可通过 POST 参数注入，链闭合，CSP 配置反而放行第三方脚本源。

**修复建议**

对 include 值做严格 URL 白名单校验（仅允许 https 且域名在固定集合内），输出时使用 htmlspecialchars($v, ENT_QUOTES) 编码；收紧 CSP script-src，移除 pastebin/hastebin/unpkg/jsdelivr 等可公开托管的域，改用 nonce/hash 或 'strict-dynamic'。

**验证说明**

需确认 020.php 的实际部署路径与是否被认证网关保护；需动态验证浏览器是否执行注入脚本及 CSP 是否放行白名单域。
模型 POC 要点：提交 include 参数闭合 src 属性并注入脚本，或指向 CSP 白名单内的可控脚本托管
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /020.php）：符合 CWE-79（跨站脚本）。漏洞位于可交付代码 020.php:17，外部输入来自 POST body 参数 include，source→sink 链在给定代码范围内静态闭合，未发现有效输出编码/净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅限授权测试。POC 为文本工件，管线不执行、不联网、不搭建沙箱。执行前将 TARGET 替换为授权目标；如需验证执行效果，可在浏览器中打开构造的请求或使用受控测试页面，避免对生产环境造成影响。

### F-2: 020.php 中 CSP script-src 白名单过宽导致脚本注入防护失效（CWE-693）

- **类型**：`csp` / CWE-693
- **严重度**：`medium`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`020.php:2-3`
- **来源**：`rule`

**描述**

020.php 第 3 行构造并输出 Content-Security-Policy 响应头，其 script-src 指令为 'self' 加上 https://pastebin.com、hastebin.com、www.toptal.com、example.com、code.jquery.com、https://ssl.google-analytics.com、unpkg.com、cdn.jsdelivr.net、digi.ninja 等大量第三方源。攻击者无需向本应用注入任何内容：只要能在上述任一允许域上托管或发布内容（pastebin.com、hastebin.com 为公开可写粘贴站，unpkg.com、cdn.jsdelivr.net 为公开 CDN，digi.ninja 为第三方站点），即可获得被 CSP 明确授权的脚本执行源。当页面存在任何 HTML 注入点（反射或存储）时，攻击者只需插入 <script src="https://pastebin.com/raw/xxxx"> 即可绕过 CSP 执行任意 JS。校验无效的原因在于策略本身把不可信/公开可写域列为可信脚本源，且未使用 nonce、hash 或 strict-dynamic，也未配置 object-src 'none'、base-uri 'self' 等收敛指令。输入中未提供 020.php 的完整响应输出代码与页面渲染逻辑，因此“页面确实存在可注入的 HTML 汇点”这一环证据不足，仅能确认策略配置缺陷本身。

**source / sink**

- source：query `include`（020.php）
- sink：020.php:3 $headerCSP = "Content-Security-Policy: script-src 'self' https://pastebin.com hastebin.com www.toptal.com example.com code.jquery.com https://ssl.google-analytics.com unpkg.com cdn.jsdelivr.net digi.ninja ;"; // allows js from various trusted locations

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `020.php:3` | CSP 与可控脚本来源联动；需检查最终响应和浏览器加载结果 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /020 的 CSP（内容安全策略）配置缺陷 POC。该端点响应缺少或配置了过于宽松的 Content-Security-Policy 头，无法有效限制内联脚本与外部脚本源，削弱了对 XSS 的纵深防御。目标地址统一使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/020'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 CSP 配置缺陷 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/020?include=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-582e93de1b73`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

CSP 作为 XSS 的最后一道纵深防御被实质性削弱：一旦应用任何位置出现 HTML/属性注入，攻击者可借助 pastebin.com、hastebin.com、unpkg.com、cdn.jsdelivr.net 等公开可写源加载任意脚本，实现会话劫持、凭据窃取、页面内容篡改与钓鱼，且浏览器不会拦截。属于防护机制失效类缺陷，本身不直接造成数据泄露。

**CVE / CWE 论证**

CWE-693（Protection Mechanism Failure）：安全机制（CSP）配置不当导致其保护目标无法达成。外部可达性：该响应头随 020.php 的 HTTP 响应返回，任何访问者均可获得，无需认证。利用链闭合度：策略过宽这一环已由 020.php:3 的原文证据确认；但“存在可注入 HTML 汇点 → 加载白名单域脚本 → 执行”这一后半链在给定 code_pack 中缺少对应渲染/输出代码，故不宣称完整 RCE/XSS 链闭合，仅认定配置型弱点成立。

**修复建议**

1) 移除 pastebin.com、hastebin.com、unpkg.com、cdn.jsdelivr.net、digi.ninja 等公开可写或非必要第三方源，仅保留业务确需的源；2) 改用基于 nonce 或 hash 的严格策略，例如 script-src 'nonce-<随机值>' 'strict-dynamic'，nonce 每次响应随机生成且不可预测；3) 补充 object-src 'none'; base-uri 'self'; frame-ancestors 'self'；4) 若必须使用 CDN，固定到具体版本路径并配合 SRI（integrity 属性）；5) 将 CSP 头集中在一处统一下发，避免散落拼接导致遗漏。

**验证说明**

静态证据：入口 ANY /020；source=query/include；sink=020.php:3；规则 php-csp-policy。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者访问 020.php → 服务器在第 3 行拼接并返回含过宽 script-src 白名单的 CSP 头 → 浏览器将该白名单域视为可信脚本源 → 攻击者在 pastebin.com/hastebin.com/unpkg.com 等公开可写域托管恶意 JS → 在应用任一 HTML 注入点插入指向该域的 <script src> → 浏览器依据 CSP 放行并执行脚本。当前证据仅覆盖“策略过宽”环节，注入点环节证据不足。
PocWriter 建议（未采纳，缺少端点 /020）：符合 CWE-693（防护机制失效）。问题位于可交付代码 020.php:3 的响应头配置，属于配置型候选，无 HTTP 污点但依据响应头/策略证据判定；具备远程可观测条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅限授权测试。POC 为文本工件，管线不执行、不联网、不搭建沙箱。执行前将 TARGET 替换为授权目标；重点检查响应头 Content-Security-Policy 的存在性与指令严格程度，而非请求参数本身。

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
| `xss` | CWE-79 | 是 | 1 |
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
| `csp` | CWE-693 |  | 1 |
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.78 | 是 |
| surface_mapper | 攻击面测绘 | 9.08 | 是 |
| deep_finder | LLM 深挖 | 7.69 | 是 |
| candidate_screener | 候选筛选 | 6.03 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.91 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.61 | 是 |
| coordinator | 管线协调 | 6.79 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
