# 落日二号乙漏洞挖掘报告 — 20261031-163839-b6e66a

- 生成时间：2026-10-31T08:39:14.249816+00:00
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

本次汇总仅含 1 条已去重 finding：SEM-0cc72d7ef5ac，类型 api_info_disclosure（CWE-200），严重度 high，位于 001.php 第 7 行，标题为页面直接暴露 OpenAPI 文档链接；该条带 POC（has_poc=true），但证据等级为规则命中，且标题自述“证据不足”，需人工确认暴露内容是否真属敏感信息。最高危即此条。整体覆盖极薄：仅 1 个文件、1 种语言（php）、0 个端点、无框架，攻击面测绘明确说明输入未提供 001.php 源码内容，因此所有注入类与配置类判断都停留在攻击面层面，不能作为 finding。POC 齐全性方面，唯一 finding 有 POC，但属静态/规则级证据，不能宣称已动态复现。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1277 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 001.php（20 行），内容为静态 HTML 说明文本：第 3 行初始化 $message，第 5-18 行向未初始化的 $html 追加一段固定字符串（含指向 openapi.yml 的链接与 DVWA 路径说明），第 20 行结束 PHP 块。全文没有任何外部输入读取（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER/$_FILES）、没有 include/require、没有文件操作、没有 exec/system/popen/shell_exec、没有数据库调用、没有 echo/print 输出 $html 或 $message、没有 md5/sha1/rand/mt_rand/setcookie 等配置型风险点。因此不存在可闭合的 source→sink 链，也不存在 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 的算法或标志位证据。surface_notes 中提到的注入类与配置类攻击面均停留在假设层面，未在代码中得到任何印证，按零容忍误报原则不予报告。未闭合线索：脚本引用的 openapi.yml 与 /vulnerabilities/api/v2/health/* 接口（DVWA API v2）不在 code_pack 内，按契约视为不存在，无法审计；$html 未初始化在 PHP 中会产生 notice 但不构成安全漏洞。输入中未出现诱导性文本，无 prompt_injection 证据。

未覆盖 / 证据缺口：
- 001.php 全文已逐行审计，无外部输入与危险汇点
- openapi.yml 及 DVWA API v2 health 接口源码未在 code_pack 中提供，无法审计
- 无路由/认证/部署配置信息，无法评估运行时暴露面
- 无依赖清单与版本历史，无法评估第三方组件 CVE

## 3. Findings

### F-1: 001.php 页面直接暴露 OpenAPI 文档链接（CWE-200 信息泄露，证据不足）

- **类型**：`api_info_disclosure` / CWE-200
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`001.php:6-7`
- **来源**：`rule`

**描述**

候选证据仅覆盖 001.php 第 6-7 行：第 7 行是一段静态 HTML，包含指向 openapi.yml 的链接（`<a href='openapi.yml'>OpenAPI</a>`），并提示读者查看 health 函数。该行没有任何来自请求的输入（无 getParameter/getHeader/Cookie 读取），也没有把用户可控数据写入响应的变量或函数调用；因此不存在 source→sink 污点链，攻击者输入点、经过的变量/函数、校验失效环节均无法从给定片段中确认。所谓“API 信息泄露”目前只能理解为：页面公开引用了 OpenAPI 描述文件路径，属于静态内容暴露，而非由请求参数驱动的数据泄露。

**source / sink**

- source：repository `API response user object`（001.php）
- sink：001.php:7 		Here is the <a href='openapi.yml'>OpenAPI</a> document, have a look the health functions and see if you can find one that has a vulnerability.

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `001.php:7` | API 端点/字段暴露；需对比版本、鉴权和返回字段 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（离线审查，不发送请求）：`001.php` 第 7 行在页面中直接暴露了 `openapi.yml` 的链接，并提示读者查看 health 相关函数是否存在漏洞。该行本身属于信息暴露/攻击面提示（CWE-200 类），并非硬编码凭据或弱算法调用；当前证据只能证明“接口文档入口被公开引用”，不能证明凭据有效或算法被弱使用。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 001.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-0cc72d7ef5ac`
- 风险提示：HTTP POC 未使用 TARGET 占位符, 请求未包含 finding 端点 /001, 请求未体现 HTTP 方法 GET, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码, POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

若 openapi.yml 可被匿名访问，攻击者可获得接口清单、参数结构与 health 类函数说明，从而缩小攻击面、辅助后续针对 health 端点的探测。但输入中未提供 openapi.yml 的内容、访问控制配置或 health 端点实现，无法确认其中是否含敏感字段（内部地址、密钥、未公开端点）。当前证据只能支撑“接口文档可发现性”这一低阶信息暴露，不能支撑数据泄露或越权结论。

**CVE / CWE 论证**

对应 CWE-200（Exposure of Sensitive Information to an Unauthorized Actor）。外部可达性：001.php 为 Web 可访问页面，链接为静态输出，无需认证即可看到文档路径。但利用链不闭合：缺少 openapi.yml 的实际内容与鉴权状态证据，也缺少任何请求参数进入响应的路径，因此不满足“无需认证 + 敏感数据实际外泄”的完整论证，不宜作为已确认漏洞上报。

**修复建议**

1) 将 openapi.yml 等接口描述文件移出 Web 根目录，或通过鉴权/内网限制访问；2) 生产环境关闭调试与文档提示页面（001.php 这类引导页应仅存在于开发环境）；3) 对 OpenAPI 文档做脱敏，移除内部主机名、示例密钥、未公开端点；4) 为 health 类端点增加最小化返回字段与访问控制，避免暴露版本与依赖信息。

**验证说明**

静态证据：入口 GET /001；source=repository/API response user object；sink=001.php:7；规则 php-api-surface。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者匿名访问 001.php → 第 7 行静态 HTML 渲染出指向 openapi.yml 的链接 → 攻击者据此获取接口文档（该文件内容与访问控制未在证据中给出）→ 依据文档枚举 health 等函数进行后续探测。链条在“获取文档内容”这一步即因证据缺失而中断，且全程无请求参数参与，不构成注入型或参数驱动的信息泄露。
POC 备注：本 POC 为静态证据工件，不执行、不联网、不搭建沙箱。目标地址统一使用 `TARGET` 占位符。原始草稿中的 `grep -n -A2 -B2 '<evidence>' 001.php` 属离线审查命令，仅作说明，管线不应执行。未覆盖范围：`openapi.yml` 内容、health 端点实现、部署访问控制均不在本次 code_pack 证据内，无法确认。

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
| safety_guard | 安全防护 | 3.79 | 是 |
| surface_mapper | 攻击面测绘 | 6.21 | 是 |
| deep_finder | LLM 深挖 | 3.64 | 是 |
| candidate_screener | 候选筛选 | 2.74 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.36 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.13 | 是 |
| coordinator | 管线协调 | 6.07 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
