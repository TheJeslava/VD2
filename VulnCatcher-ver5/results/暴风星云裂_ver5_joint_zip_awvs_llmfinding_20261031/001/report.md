# 落日二号乙漏洞挖掘报告 — 20261031-213944-75428a

- 生成时间：2026-10-31T13:40:26.137190+00:00
- 输入：`$WORKSPACE\暴风星云裂\001.zip`
- 输入模式：`zip`
- SHA256：`9eef8763d9327d2537ce1467f7f2014999c659dd40d8f76a19ca38fb07bdd6c9`
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

本次汇总仅含 1 条已去重 finding：SEM-0cc72d7ef5ac（api_info_disclosure，high，001.php 第 7 行附近），规则来源，已附 POC（静态/HTTP 性质需按 POC 文本确认，本次未做动态验证）。最高危即该条信息泄露候选，但其标题自述“证据不足”，且管线未提供 001.php 源码内容，行级证据无法复核，建议按“待人工确认”处理而非直接定级。POC 齐全度为 1/1（有 POC 计数=1），但仅覆盖该单条；其余攻击面（注入、弱哈希/弱随机、Cookie 标志、信任边界）均无 findings，属未覆盖而非已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1277 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 001.php（20 行），内容为静态 HTML 说明页：第 3 行初始化 $message，第 5-18 行向未初始化的 $html 追加一段固定字符串（含指向 openapi.yml 的链接与 DVWA 使用说明），第 20 行结束 PHP 块。全文没有任何外部输入读取（无 $_GET/$_POST/$_COOKIE/$_SERVER/$_REQUEST/getenv/php://input），没有 include/require、system/exec/shell_exec/passthru/eval/assert、SQL 拼接、文件读写、反序列化、模板渲染或 setcookie/session 调用，因此不存在可闭合的 source→sink 利用链。surface_notes 中列出的 weak_hash / weak_random / insecure_cookie / weak_crypto / trust_boundary 五类候选，在可见代码中均无对应实现（无 md5/sha1、无 rand/mt_rand/uniqid、无 setcookie/session_set_cookie_params、无 mcrypt/openssl、无 X-Forwarded-For/User-Agent/Referer 读取），按配置型候选规则核对后同样不成立，故不产出 finding。唯一可记录的低价值线索是第 5 行对未定义变量 $html 的 .= 追加，在默认 error_reporting 下会产生 Undefined variable 警告并可能泄露绝对路径，属信息性噪音，不构成 CVE 级问题。未闭合/未覆盖：该文件引用的 openapi.yml 与 /vulnerabilities/api/v2/health/* 系列接口（echo 等）均不在 code_pack 内，按零工具契约视为不存在，无法审计；DVWA 主体代码、php.ini/Web 服务器配置、依赖清单也未提供，因此本次结论仅限 001.php 本身，不能推断整个部署无漏洞。

未覆盖 / 证据缺口：
- openapi.yml 未在 code_pack 中，无法审计其描述的 health 接口
- /vulnerabilities/api/v2/health/echo 等 DVWA API 实现文件未提供，无法做污点分析
- 无 php.ini / Web 服务器 / .htaccess 配置，无法评估 allow_url_include、上传目录可执行等部署风险
- 无端点清单与认证中间件信息，无法确认该脚本的实际 URL 与鉴权边界
- 无 composer.json 等依赖清单，无法评估第三方组件 CVE

## 3. Findings

### F-1: 001.php 页面直接暴露 OpenAPI 文档路径（CWE-200 信息泄露，证据不足）

- **类型**：`api_info_disclosure` / CWE-200
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`001.php:6-7`
- **来源**：`rule`

**描述**

输入给出的唯一证据是 001.php 第 6-7 行的静态 HTML 片段：第 7 行输出一个指向 `openapi.yml` 的链接，并附带一句提示性文案。该片段中不存在任何 HTTP 输入读取（无 getParameter/getHeader/Cookie 读取）、无变量拼接、无后端逻辑分支，因此不存在从攻击者输入到危险汇点的数据流。所谓“API 信息泄露”仅来自规则对“OpenAPI 文档被引用”这一语义模式的命中，属于静态页面文案，而非接口响应中泄露用户对象或敏感字段。攻击者输入点：证据不足（片段中无输入点）。经过的变量/函数：无。校验为何无效：不适用，因为没有输入进入任何处理逻辑。最终危险操作：无，仅是一个静态超链接。

**source / sink**

- source：repository `API response user object`（001.php）
- sink：001.php:7 		Here is the <a href='openapi.yml'>OpenAPI</a> document, have a look the health functions and see if you can find one that has a vulnerability.

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `001.php:7` | API 端点/字段暴露；需对比版本、鉴权和返回字段 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：`001.php` 第 7 行在页面中直接暴露了 OpenAPI 文档路径 `openapi.yml`，并提示读者查看其中的 health 函数。该行本身只是 HTML 链接文本，属于信息暴露线索（CWE-200 方向），并非已确认的敏感数据泄露；真正的接口清单需读取 `openapi.yml` 才能确认，而该文件不在本次 code_pack 范围内。

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

按现有证据无法确认任何实际影响。最坏情况下，若 `openapi.yml` 在部署环境中可被匿名访问，攻击者可获得接口清单与参数结构，从而缩小后续攻击面（信息收集辅助），但这属于部署配置问题，且输入未提供该文件内容、访问控制配置或响应样例，无法证明敏感字段（如用户对象）被返回。不构成 RCE、数据泄露、越权或文件读写。

**CVE / CWE 论证**

对应 CWE-200（Exposure of Sensitive Information to an Unauthorized Actor）。但外部可达性、无需认证、利用链闭合三项均无法从输入证据中确认：片段中没有认证逻辑、没有响应体、没有 openapi.yml 的实际内容，也没有任何污点链。因此不满足 CVE 论证所需的“外部可达 + 利用链闭合”条件，当前只能作为待复核的规则命中，不能作为已确认漏洞。

**修复建议**

1) 若 `openapi.yml` 仅用于开发调试，应在生产环境移除该静态链接并禁止匿名访问该文件（Web 服务器层返回 403/404，或将其置于需认证的路径下）；2) 对 OpenAPI 文档做访问控制或仅在内网/鉴权后提供；3) 审查文档内容，移除内部主机名、内部端点、示例密钥等敏感信息；4) 若确需公开文档，明确其为公开 API 契约并确认不含敏感字段定义。以上均需在拿到 openapi.yml 内容与部署配置后再确认必要性。

**验证说明**

静态证据：入口 GET /001；source=repository/API response user object；sink=001.php:7；规则 php-api-surface。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：证据链在第一步即中断：001.php:7 只是静态输出 `<a href='openapi.yml'>`，没有读取任何请求参数或请求头，也没有把外部数据写入响应。规则以“语义模式命中”标记为 API 信息泄露，但缺少 source（攻击者输入）、缺少跨文件证据（openapi.yml 内容与访问控制）、缺少响应字段对比。因此无法构造从攻击者输入到敏感信息输出的闭合链路，本 finding 应降级为待复核项而非确认漏洞。
POC 备注：POC 仅为文本工件，不执行、不联网。目标统一使用 TARGET 占位符。第 3 步的 openapi.yml 内容不在 code_pack 中，需补充源码/路由后再判定；不得把未验证的接口清单写成已确认事实。

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
| safety_guard | 安全防护 | 5.2 | 是 |
| surface_mapper | 攻击面测绘 | 6.88 | 是 |
| deep_finder | LLM 深挖 | 4.8 | 是 |
| candidate_screener | 候选筛选 | 3.62 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.58 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.73 | 是 |
| coordinator | 管线协调 | 7.42 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
