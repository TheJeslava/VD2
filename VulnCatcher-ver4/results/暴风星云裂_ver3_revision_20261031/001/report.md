# 落日二号乙漏洞挖掘报告 — 20261031-011403-f3f106

- 生成时间：2026-10-30T17:14:37.571709+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\001.zip`
- 输入模式：`zip`
- SHA256：`9eef8763d9327d2537ce1467f7f2014999c659dd40d8f76a19ca38fb07bdd6c9`
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

本次汇总仅含 1 条已去重 finding：001.php 第 7 行附近公开暴露 OpenAPI 文档链接，类型 api_info_disclosure（CWE-200），严重度 high，已附带 POC（HTTP 型，可请求该页面并观察文档链接）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 有 POC，但该 POC 属 HTTP 可复现类，尚未动态验证。其余攻击面（注入、文件包含、命令执行、XSS、配置类）在 surface_notes 中被列为优先人工阅读区域，但本次没有任何代码片段进入证据包，因此未产出对应 finding，不能据此认为这些类型不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1277 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单文件 001.php（20 行），内容为静态 HTML 说明页：第 3 行初始化 $message，第 5-18 行向未初始化的 $html 追加静态 HTML 字符串（含指向 openapi.yml 的链接与 DVWA API 路径说明），第 20 行结束 PHP 块。全文未出现任何外部输入读取（$_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER）、无 include/require/fopen/file_get_contents、无 system/exec/shell_exec/passthru/proc_open、无 SQL 调用、无 echo/print 输出 $html 或 $message、无 setcookie/session 配置、无 md5/sha1/rand/openssl 等加密或随机数调用、无硬编码凭据。因此不存在可闭合的 source→sink 利用链，按零容忍误报原则返回空 findings。surface_notes 中列出的注入、文件包含、命令执行、XSS、弱哈希/弱加密/弱随机/不安全 Cookie/硬编码密钥等攻击面，在本文件中均无对应代码证据，属于基于文件类型与规模的推断，不构成漏洞结论。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- 001.php 全文 20 行已完整审计（shown_ranges 1-20，truncated=false），无未覆盖行
- 仓库仅此 1 个文件，无跨文件调用链、无 composer.json 依赖、无 php.ini/.env/Web 服务器配置，无法评估部署方式与组件级 CVE
- 无 HTTP 端点/路由清单，001.php 的实际可达性与参数名无法确认（但代码本身不读取任何参数，故不影响结论）
- surface_notes 提到的 openapi.yml 与 /vulnerabilities/api/v2/health/* 接口不在 code_pack 内，按契约视为不存在，未审计

## 3. Findings

### F-1: 001.php 页面公开暴露 OpenAPI 文档链接（信息泄露，CWE-200）

- **类型**：`api_info_disclosure` / CWE-200
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`001.php:6-7`
- **来源**：`rule`

**描述**

证据来自 001.php 第 6-7 行：页面正文直接输出一个指向 `openapi.yml` 的 HTML 链接，并附带提示语，引导访问者查看 health 相关函数并寻找漏洞。攻击者无需任何输入或认证，只需请求该页面（如 GET /001.php），即可从响应 HTML 中获知 OpenAPI 描述文件的位置；随后直接请求该静态文件即可获取全部 API 端点、参数结构、鉴权方式与内部函数命名。此处不存在参数校验环节，因为泄露并非由用户输入触发，而是页面硬编码输出所致，属于设计层面的信息暴露而非污点链漏洞。需要说明：输入证据仅包含 001.php 第 6-7 行片段，未提供 openapi.yml 的实际内容，因此“文档中是否包含敏感端点/内部字段”属于推断，证据不足。

**source / sink**

- source：request `API version/user object`（001.php）
- sink：001.php:7 		Here is the <a href='openapi.yml'>OpenAPI</a> document, have a look the health functions and see if you can find one that has a vulnerability.

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `001.php:7` | API 端点/字段暴露；需对比版本、鉴权和返回字段 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /001（ANY）的 API 信息泄露 POC。注入点：ANY 参数 API version/user object；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/001'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 API 信息泄露 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/001?API version/user object=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-0cc72d7ef5ac`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

信息泄露：未认证的远程访问者可枚举 API 攻击面（端点路径、HTTP 方法、参数名与类型、鉴权要求、health/调试类函数），显著降低后续针对 health 函数的漏洞挖掘成本，可能进一步导致未授权功能调用或敏感数据读取；具体敏感字段因缺少 openapi.yml 内容而证据不足。

**CVE / CWE 论证**

CWE-200（Exposure of Sensitive Information to an Unauthorized Actor）。外部可达性：001.php 为可直接请求的 Web 页面，无需认证；利用链闭合：请求页面 → 响应 HTML 含 `openapi.yml` 链接 → 请求该文件获取 API 描述。但该问题本质是部署/设计层面的文档暴露，通常不单独分配 CVE，且是否构成实质敏感信息泄露取决于 openapi.yml 内容（证据不足），故不宜按 CVE 级漏洞定级。

**修复建议**

1) 生产环境不部署 openapi.yml 等 API 描述文件，或将其置于需认证的路径下；2) 若必须提供文档，使用独立文档站点并加访问控制（HTTP Basic/SSO）与 IP 白名单；3) 从面向公网的页面中移除指向内部文档与 health 函数的提示性文案；4) 对 health/调试类端点实施鉴权或仅绑定内网回环地址；5) 在网关层对 `*.yml`、`*.yaml`、`/openapi*` 路径返回 404。

**验证说明**

静态证据：入口 ANY /001；source=request/API version/user object；sink=001.php:7；规则 php-api-surface。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者发送 GET 请求访问 001.php（无需认证）→ 服务器返回第 6-7 行硬编码的 HTML，其中 `<a href='openapi.yml'>` 暴露文档路径 → 攻击者据此直接请求 openapi.yml，获得完整 API 端点与参数清单 → 结合页面提示定位 health 函数，作为后续漏洞利用的入口。整条链不依赖任何用户可控输入，属于被动信息暴露。
PocWriter 建议（未采纳，缺少端点 /001）：针对 001.php:7 的 API 信息泄露（CWE-200）POC 文本。外部输入来自查询串中的参数名 `API version/user object`（含空格与斜杠，需 URL 编码），在 001.php:7 处未经有效净化即被使用，导致接口/版本/用户对象等敏感信息可能被回显。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /001）：符合 CWE-200（敏感信息暴露）。证据定位 001.php:7，外部输入来自查询串参数 `API version/user object`，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。原始草稿中的 `curl -sS -i -X ANY ...` 与 request.http 结构予以保留，仅补充 URL 编码说明与基线对比步骤；`ANY` 为占位方法，实际测试时按目标支持的方法（GET/POST 等）替换。禁止将脚本改为自动执行或管道执行形式。

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
| `api_info_disclosure` | CWE-200 |  | 1 |
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
| safety_guard | 安全防护 | 3.22 | 是 |
| surface_mapper | 攻击面测绘 | 8.89 | 是 |
| deep_finder | LLM 深挖 | 2.94 | 是 |
| candidate_screener | 候选筛选 | 2.71 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.81 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.39 | 是 |
| coordinator | 管线协调 | 5.16 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
