# 落日二号乙漏洞挖掘报告 — 20261031-164451-df4cd2

- 生成时间：2026-10-31T08:45:24.937472+00:00
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

本次汇总仅含 1 条已去重 finding：SEM-2ffadbadfdc4，类型 client_side_validation（CWE-602），严重度 high，位于 033.php 第 2 行，判定为仅依赖外部 JavaScript 做客户端校验、服务端缺少对应校验。该条已附带 POC（has_poc=true），但属静态/代码级证据 POC，未做动态验证。最高危即此条 high。整体覆盖度很低：仓库仅 1 个 PHP 文件、3 行 131 字节，无端点清单、无框架、无 source/sink 热点标注，surface_notes 明确说明未提供源码片段，因此 command_injection / sql_injection / xss / path_traversal / ssrf 等一次注入以及硬编码凭据均无法判断，不能视为已排除。POC 齐全度：1/1 条 finding 有 POC，但均为静态证据，不可宣称可动态复现。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 168 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单文件 033.php（3 行，131 字节），内容为 DVWA 的 JavaScript 漏洞模块页面片段：第 2 行将常量 DVWA_WEB_PAGE_TO_ROOT 与固定字符串 'vulnerabilities/javascript/source/medium.js' 拼接后追加到 $page['body']，第 3 行结束 PHP 块。该文件不含任何外部输入读取（无 $_GET/$_POST/$_COOKIE/$_SERVER/$_REQUEST）、无文件/命令/SQL/模板/反序列化 sink、无 setcookie/session 调用、无 md5/sha1/rand/openssl 等弱算法调用，也无硬编码凭据。拼接的字符串全部为常量与字面量，攻击者无法控制，因此不存在可闭合的 source→sink 利用链。surface_notes 中列出的 weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary 五类候选，经逐行核对均无对应实现证据，属未证实线索而非漏洞，故不单独立项。DVWA_WEB_PAGE_TO_ROOT 的定义、$page 数组的初始化与最终输出位置均在本 code_pack 之外，按零工具契约视为不存在，未做推断。

未覆盖 / 证据缺口：
- DVWA_WEB_PAGE_TO_ROOT 常量定义与 $page 数组初始化/渲染逻辑不在 code_pack 内，无法确认最终输出上下文（若该常量可被外部影响才可能形成 XSS，但当前无证据）
- 无 Web 服务器配置、php.ini、路由/包含链信息，实际可达路径与暴露面未确认
- 无 PHP 版本与扩展信息，无法评估版本相关风险
- surface_notes 提到的参数名遍历、Runtime.exec 环境变量数组、路径拼接等特殊入口/汇点在给定代码中均不存在

## 3. Findings

### F-1: 033.php 仅通过外部 JavaScript 引入客户端校验（CWE-602）

- **类型**：`client_side_validation` / CWE-602
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`033.php:1-2`
- **来源**：`rule`

**描述**

证据仅覆盖 033.php 第 1-2 行：第 2 行通过字符串拼接把 DVWA_WEB_PAGE_TO_ROOT . 'vulnerabilities/javascript/source/medium.js' 作为 <script src> 输出到 $page['body']。该片段中不存在任何服务端接收参数（无 $_GET/$_POST/$_REQUEST/getParameter 等）、不存在服务端校验函数、也不存在危险汇点（无 SQL、文件、命令、反序列化调用）。因此攻击者输入点、经过的变量/函数、校验失效的具体原因均无法从给定代码确认；medium.js 的内容不在 code_pack 内，无法判断其校验逻辑是否可被绕过，也无法判断服务端是否重复校验。按证据边界，本条只能确认“校验逻辑被放在客户端脚本中”这一实现事实，不能确认可利用的绕过链。

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

证据不足。若 medium.js 中的校验为唯一校验且服务端未复校，理论上攻击者可绕过前端限制提交非法数据；但当前片段未展示任何被校验的业务参数及其服务端处理，无法说明具体影响（RCE/数据泄露/越权/文件读写均无证据）。

**CVE / CWE 论证**

CWE-602（Client-Side Enforcement of Server-Side Security）。外部可达性：033.php 为 Web 页面，可被远程访问；无需认证：片段中无任何鉴权判断，但同样无业务逻辑，无法确认。利用链闭合性：不闭合——缺少 source（攻击者可控输入）、缺少服务端 sink、缺少 medium.js 内容，无法证明绕过客户端校验后能达成任何安全影响。因此不满足 CVE 论证所需的“可达 + 可控 + 危险汇点”三要素。

**修复建议**

1) 在服务端对同一业务参数实施与客户端等价的强校验（白名单/类型/长度/范围），客户端脚本仅作体验优化；2) 服务端校验失败时返回明确错误而非静默放行；3) 若涉及敏感操作，增加服务端会话与权限校验；4) 将 medium.js 纳入审计范围以确认其校验规则，并在服务端镜像实现。

**验证说明**

静态证据：入口 ANY /033；source=client/external JavaScript；sink=033.php:2；规则 php-client-validation。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：已确认：033.php:2 将外部脚本 vulnerabilities/javascript/source/medium.js 注入页面 body，说明校验逻辑位于客户端。缺口：未提供 medium.js 内容、未提供服务端接收该数据的参数名与处理代码、未提供任何危险汇点。故无法构造“攻击者输入 → 绕过客户端校验 → 服务端危险操作”的闭合链，本条维持低置信度推断。
PocWriter 建议（未采纳，缺少端点 /033）：针对 033.php:2 的客户端校验绕过（CWE-602）POC 文本。源码中外部输入来自 query 参数 include，但当前证据未给出该参数在服务端的实际使用方式（是否回显、是否参与 include/文件读取、是否有前端 JS 校验），因此本 POC 仅保留确定性草稿的请求结构，用于对比基线与带 payload 的响应差异，不宣称已确认的利用效果。
PocWriter 建议（未采纳，缺少端点 /033）：对应 CWE-602（客户端安全依赖）。证据等级：llm_inferred。漏洞位置 033.php:2，外部输入为 query 参数 include；但证据中未给出该参数到危险汇点的完整数据流，也未给出前端校验代码，因此 source→sink 链尚未静态闭合，不能作为已验证结论。
POC 备注：仅保留文本工件，不执行、不联网、不搭建沙箱。草稿中的 -X ANY 不是合法 HTTP 方法，已改为 GET；若源码确认使用 POST，需改为 POST 并在 body 中携带 include=SUNSET_PROBE 及触发按钮字段（字段名需补充源码）。目标地址统一使用 TARGET，端口按实际部署调整。

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
| safety_guard | 安全防护 | 2.69 | 是 |
| surface_mapper | 攻击面测绘 | 5.55 | 是 |
| deep_finder | LLM 深挖 | 3.31 | 是 |
| candidate_screener | 候选筛选 | 2.8 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.29 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.6 | 是 |
| coordinator | 管线协调 | 5.61 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
