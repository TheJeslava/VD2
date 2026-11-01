# 落日二号乙漏洞挖掘报告 — 20261031-172422-4b0378

- 生成时间：2026-10-31T09:25:00.431953+00:00
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

本次管线仅交付 1 条 finding：001.php 第 7 行附近直接暴露 OpenAPI 文档链接，类型 api_info_disclosure，严重度 high，来源为规则命中，已附带 POC（HTTP 型，可对 TARGET 请求该页面观察文档链接）。该条证据等级偏弱——surface_notes 明确说明输入未提供任何代码行内容，因此该结论只能视为规则级线索，需人工通读 001.php 全文确认链接是否真实指向可访问的接口文档。最高危即此条。POC 齐全度为 1/1（仅就本条而言），但注入类、文件包含类、命令执行类、SQL 注入类、输出反射类以及全部配置类候选均无证据级结论，属于未覆盖而非未检出。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1277 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含一个 20 行的 PHP 文件 001.php，内容为静态 HTML 提示页：第 3 行初始化 $message，第 5-18 行向 $html 追加一段固定说明文本（指向 openapi.yml、DVWA 的 /vulnerabilities/api/v2/health/echo 等），第 20 行结束 PHP 标签。全文没有任何外部输入读取（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER）、没有 include/require、没有 system/exec/shell_exec/passthru/proc_open、没有数据库调用、没有文件读写、没有 echo/print 输出用户数据、没有 header() 拼接、没有 md5/sha1/rand/setcookie 等配置类证据。因此不存在可闭合的 source→sink 利用链，也不存在配置型候选（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary/hardcoded_secret 均无对应代码）。surface_notes 中列出的六个优先攻击面（参数入口、文件包含、命令执行、SQL 注入、输出反射、配置类）在本文件中逐一核对后均无落地代码，属于纯测绘假设而非证据。未闭合线索：surface_notes 提到的 openapi.yml 与 /vulnerabilities/api/v2/health/* 端点不在 code_pack 内，按契约视为不存在，无法审计；DVWA 实际漏洞代码未送入。未发现满足 CVE 级别且链闭合的漏洞，按‘宁可漏报不可误报’原则返回空结果。

未覆盖 / 证据缺口：
- openapi.yml 未在 code_pack 中，无法审计其描述的 health 接口实现
- /vulnerabilities/api/v2/health/* 对应的后端源码未提供，无法评估是否存在注入/命令执行等漏洞
- 无部署配置（php.ini、Web 服务器配置），无法确认 allow_url_include、open_basedir 等运行时条件
- 无端点清单与路由信息，001.php 的实际访问路径与访问控制未知

## 3. Findings

### F-1: 001.php 页面直接暴露 OpenAPI 文档链接（CWE-200 信息泄露，证据不足）

- **类型**：`api_info_disclosure` / CWE-200
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`001.php:6-7`
- **来源**：`rule`

**描述**

输入给出的唯一证据是 001.php 第 6-7 行的静态 HTML：第 7 行输出一个指向 openapi.yml 的 <a href> 链接，并附文字提示读者查看 health 函数。该行不含任何 getParameter/getHeader/Cookie 读取，也不含数据库或文件读取逻辑，因此不存在攻击者可控输入进入危险汇点的链路。所谓“API 信息泄露”仅来自规则对“OpenAPI 文档被引用”这一语义模式的命中，属于推断而非已证实的泄露：openapi.yml 的实际内容、是否可匿名访问、是否包含内部端点或凭据，均未在 code_pack 中提供。

**source / sink**

- source：repository `API response user object`（001.php）
- sink：001.php:7 		Here is the <a href='openapi.yml'>OpenAPI</a> document, have a look the health functions and see if you can find one that has a vulnerability.

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `001.php:7` | API 端点/字段暴露；需对比版本、鉴权和返回字段 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

001.php 第 7 行在页面中直接暴露了 OpenAPI 文档入口（<a href='openapi.yml'>OpenAPI</a>），并提示读者去查看 health 相关接口。该页面把内部 API 描述文件路径公开给任意访问者，属于 API 信息泄露（CWE-200）：攻击者可据此枚举接口、参数与健康检查端点，为后续探测提供地图。证据等级：llm_inferred（基于源码静态推断，未做动态验证）。

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

证据不足。若 openapi.yml 可被未认证访问且包含内部/未授权端点、调试参数或示例凭据，则可能为攻击者提供接口枚举与后续攻击面测绘的便利（信息泄露，非直接 RCE/越权）。当前仅有页面中的链接文本，无法确认实际泄露内容与影响范围。

**CVE / CWE 论证**

CWE-200（向未授权方暴露信息）。外部可达性：001.php 为可直接请求的页面，无需认证即可读取第 7 行链接。但利用链不闭合——缺少 openapi.yml 内容、访问控制配置与敏感字段证据，无法证明“敏感信息”实际暴露，故不满足 CVE 级别的闭合论证。

**修复建议**

1) 若 openapi.yml 仅面向内部，应移出 Web 根目录或加鉴权（如基于会话/角色的访问控制），不要以静态文件形式公开；2) 对外发布的规范应裁剪内部端点、调试参数、示例密钥与内网地址；3) 生产环境关闭此类“提示找漏洞”的说明性页面；4) 对 /openapi.yml 增加访问日志与最小权限校验。

**验证说明**

静态证据：入口 GET /001；source=repository/API response user object；sink=001.php:7；规则 php-api-surface。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 001.php → 第 7 行返回指向 openapi.yml 的链接 → （推断）攻击者进一步请求 openapi.yml 获取接口清单。链路在第二步即中断：code_pack 未提供 openapi.yml 内容与鉴权配置，无法证明敏感信息实际可读，故仅为语义模式命中。
POC 备注：POC 为文本工件，不执行、不联网。目标统一使用 TARGET 占位符。第 3 步的 health 路径需在拿到 openapi.yml 后填入真实路径，未确认前不得伪造。若 openapi.yml 返回 401/403，应在报告中注明泄露仅限链接存在。

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
| safety_guard | 安全防护 | 4.28 | 是 |
| surface_mapper | 攻击面测绘 | 8.65 | 是 |
| deep_finder | LLM 深挖 | 3.84 | 是 |
| candidate_screener | 候选筛选 | 2.73 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.35 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.52 | 是 |
| coordinator | 管线协调 | 7.77 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
