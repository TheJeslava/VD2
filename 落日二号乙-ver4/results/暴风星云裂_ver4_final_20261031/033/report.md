# 落日二号乙漏洞挖掘报告 — 20261031-173028-1aaf9d

- 生成时间：2026-10-31T09:31:01.136559+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\033.zip`
- 输入模式：`zip`
- SHA256：`2cc6995b797e45b354fcf30552f7b1dba5f3ce341ebf99c3f25eb6325b4dee16`
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

本次汇总仅含 1 条已去重 finding：SEM-2ffadbadfdc4，类型 client_side_validation（CWE-602），严重度 high，位于单文件 PHP 脚本 033.php 第 2 行，来源为规则命中，已附带 POC。最高危项即该客户端校验绕过，但需注意其证据来自规则匹配，且输入未提供 033.php 的代码正文，无法确认服务端是否真的缺少对应校验，因此该结论属静态/规则级，未经动态验证。POC 齐全度为 1/1（该条有 POC），但仅此一条，其余攻击面（命令注入、SQL 注入、路径穿越、XSS、弱哈希/弱加密/弱随机、不安全 Cookie、信任边界）均无 finding 交付，属覆盖不足而非已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 168 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 033.php 一个文件（3 行，131 字节），已逐行审计。内容为：第 1 行 PHP 开标签；第 2 行向 $page['body'] 追加一个指向 DVWA_WEB_PAGE_TO_ROOT . 'vulnerabilities/javascript/source/medium.js' 的 script 标签；第 3 行闭标签。该文件不含任何外部输入接收（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER 读取）、无 include/require、无 system/exec/shell_exec、无数据库调用、无文件读写、无 echo 输出用户数据、无 md5/sha1/rand/setcookie/session 等配置型风险特征。拼接进 HTML 的字符串由常量 DVWA_WEB_PAGE_TO_ROOT 与固定字面量组成，攻击者不可控，不构成 XSS 或路径穿越。因此无可闭合的 source→sink 利用链，findings 为空。未闭合线索：DVWA_WEB_PAGE_TO_ROOT 的定义、medium.js 的内容、以及该页面是否被 Web 服务器直接暴露，均不在 code_pack 内，按契约视为不存在，无法进一步评估；surface_notes 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 候选在本文件中均无对应代码证据，属未证实而非已排除。输入中未出现诱导性文本，无 prompt_injection 证据。

未覆盖 / 证据缺口：
- DVWA_WEB_PAGE_TO_ROOT 常量定义文件未在 code_pack 中，无法确认其是否可被外部影响
- vulnerabilities/javascript/source/medium.js 内容未提供，无法评估其客户端逻辑
- 缺少 Web 服务器/php.ini 部署配置，无法确认该脚本是否对外暴露及危险配置项
- 无端点清单与依赖清单，无法评估路由与第三方组件

## 3. Findings

### F-1: 033 客户端校验绕过（CWE-602）

- **类型**：`client_side_validation` / CWE-602
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`033.php:1-2`
- **来源**：`rule`

**描述**

证据仅覆盖 033.php 第 1-2 行：第 2 行通过字符串拼接把外部脚本 `vulnerabilities/javascript/source/medium.js` 引入页面 body（`$page['body'] .= '<script src="' . DVWA_WEB_PAGE_TO_ROOT . 'vulnerabilities/javascript/source/medium.js"></script>'`）。该脚本属于客户端校验逻辑，攻击者可在浏览器端直接修改或跳过该脚本、或直接向服务端提交请求，从而绕过前端校验。但输入中未提供 medium.js 的具体校验内容，也未提供服务端处理端点（如接收表单的 PHP 文件）是否重复校验的证据，因此「校验无效」这一环在现有证据下无法闭合。

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

若服务端确实依赖该客户端脚本做安全决策，攻击者可绕过前端校验提交任意数据，可能导致业务规则绕过或后续注入类风险。具体影响面（是否可导致越权/数据篡改）证据不足，无法确认。

**CVE / CWE 论证**

CWE-602（Client-Side Enforcement of Server-Side Security）：安全决策放在客户端执行，攻击者完全控制客户端环境即可绕过。外部可达性：该脚本随页面加载，任何访问该页面的未认证用户均可获取并分析；无需认证即可构造绕过请求。但利用链闭合性不足——缺少服务端校验缺失的直接证据，故不能断言完整可利用。

**修复建议**

在服务端对所有关键校验逻辑重新实现并强制执行，客户端脚本仅作为用户体验优化；对提交数据做白名单/类型/长度校验；不要将安全决策（如权限、金额、状态）交由前端 JS 判断；对服务端入口做统一参数校验与输出编码。

**验证说明**

静态证据：入口 ANY /033；source=client/external JavaScript；sink=033.php:2；规则 php-client-validation。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者访问 033.php → 页面第 2 行加载 medium.js 执行客户端校验 → 攻击者通过浏览器开发者工具禁用/修改该脚本或直接构造 HTTP 请求 → 若服务端未重复校验则绕过成功。当前证据只到「加载客户端脚本」这一步，服务端是否缺失校验未在 code_pack 中体现，链条未闭合。
PocWriter 建议（未采纳，缺少端点 /033）：针对 033.php:2 的客户端校验绕过（CWE-602）POC 文本。源码中外部输入来自 query 参数 include，但输入未提供 033.php 的具体代码行内容，无法确认该参数在服务端的实际使用方式（是否回显、是否参与文件包含、是否仅前端校验）。因此本 POC 仅保留确定性草稿的请求结构，并标注需补充源码确认的字段。
PocWriter 建议（未采纳，缺少端点 /033）：符合 CWE-602（客户端安全校验依赖）。漏洞位置 033.php:2，外部输入来自 query 参数 include；但输入未提供该行源码内容，source→sink 链的闭合性无法在本阶段独立复核，证据等级为 llm_inferred。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。草稿中的 ANY 方法与 curl 脚本保留为参考，实际执行前须按源码确认 HTTP 方法与参数名；目标统一使用 TARGET 占位符，仅限授权测试。

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
| safety_guard | 安全防护 | 3.58 | 是 |
| surface_mapper | 攻击面测绘 | 6.36 | 是 |
| deep_finder | LLM 深挖 | 3.17 | 是 |
| candidate_screener | 候选筛选 | 2.83 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.11 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.16 | 是 |
| coordinator | 管线协调 | 6.03 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
