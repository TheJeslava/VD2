# 落日二号乙漏洞挖掘报告 — 20261031-215027-ccfd94

- 生成时间：2026-10-31T13:51:03.859326+00:00
- 输入：`$WORKSPACE\暴风星云裂\052.zip`
- 输入模式：`zip`
- SHA256：`6b53fa2c4a30c16747b1ae8a0236ae3f7fb52d1a4bc7e7999805f539e733c540`
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

本次汇总仅含 1 条已去重 finding：052.php 第 3 行外部输入经第 11 行附近输出形成反射型 XSS（medium，LLM-4be6b4e0336a），已附 POC，属 HTTP 可复现类型。最高危即该条 medium XSS，无 high/critical。POC 齐全度：1/1 有 POC，但均为静态源码推断产物，未经动态验证。整体样本为单文件 PHP（14 行），攻击面窄、证据稀薄，sink 热点为空，注入类结论仅此一条落地。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 409 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 CODE PACK 中唯一文件 052.php（14 行，已完整展示 1-14 行）。确认第 6 行 $_GET['name'] 为外部输入，第 8 行黑名单正则非递归且仅覆盖 script 字面量，第 11 行未编码直接拼入 HTML 输出，第 3 行关闭 X-XSS-Protection，构成可绕过的反射型 XSS，已给出闭合利用链与 POC。未发现 include/require、文件读写、SQL、命令执行等其它 sink，故无 path_traversal/LFI/RCE 类结论。surface_notes 中提到的 trust_boundary 复核项经核对第 3 行实为 header() 调用而非输入读取，热点标注与实际代码不符，未形成可利用链，故不单独立项。未覆盖范围：无部署配置（open_basedir、PHP 版本）、无其它文件，无法评估跨文件调用与配置类风险。

未覆盖 / 证据缺口：
- 无 HTTP 端点清单与部署配置，无法评估服务器层影响
- 仅单文件，无法判断是否存在跨文件调用链
- 未提供 PHP 版本，无法确认特定版本行为差异

## 3. Findings

### F-1: 052.php 参数 name 反射型 XSS（preg_replace 黑名单可被嵌套标签绕过）

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `externally_corroborated`
- **位置**：`052.php:6-11`
- **来源**：`llm_finding`

**描述**

052.php 第 6 行从 $_GET['name'] 读取外部输入，第 8 行仅用正则 /<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i 删除形如 <...script...> 的子串，第 11 行将结果直接拼进 "<pre>Hello {$name}</pre>" 输出，未做 htmlspecialchars 等 HTML 实体编码；第 3 行还主动发送 X-XSS-Protection: 0 关闭浏览器 XSS 过滤器。由于正则只匹配一次且不递归，攻击者可用嵌套/拆分标签（如 <scr<script>ipt>alert(1)</script> 或 <img src=x onerror=alert(1)>）绕过黑名单，使浏览器解析出可执行脚本，构成反射型 XSS。

**source / sink**

- source：query `name`（052.php:6）
- sink：052.php:11 echo/输出 $html，其中 $html .= "<pre>Hello {$name}</pre>"（第 11 行字符串拼接后输出）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `052.php:6` | 检查 $_GET 中存在 name 且非 NULL，读取攻击者可控参数 | 原始外部字符串 |  |
| 2 | `052.php:8` | preg_replace 用单次非递归正则删除匹配 <...script...> 的子串 | 仅删除首个匹配的 script 标签片段，其余 HTML 原样保留 | 正则非递归且只做一次替换，嵌套标签 <scr<script>ipt> 删除内层后重新拼成 <script>；且完全不拦截 <img onerror>、<svg onload> 等非 script 向量 |
| 3 | `052.php:11` | 将未编码的 $name 拼入 HTML 并输出 | 含可执行 HTML/JS 的响应体 |  |
| 4 | `052.php:3` | 响应头 X-XSS-Protection: 0 关闭浏览器内置 XSS 过滤 | 浏览器不再拦截反射型脚本 |  |

**POC**

针对 /052.php（GET）的反射型跨站脚本（CWE-79）POC。源码 052.php 第 11 行将 GET 参数 name 的值直接输出到响应页面，未做 HTML 实体编码，导致注入的 <script> 在受害者浏览器中执行。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/052.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/052.php?name=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-4be6b4e0336a`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可在受害者浏览器上下文执行任意 JavaScript，窃取会话/凭证、伪造操作或进行钓鱼；X-XSS-Protection: 0 进一步降低浏览器侧防护。

**CVE / CWE 论证**

CWE-79 跨站脚本。外部 GET 参数 name 无需认证即可控制，经可绕过的黑名单过滤后直接进入 HTML 输出，source→sink 链在 CODE PACK 内完整闭合。

**修复建议**

输出前使用 htmlspecialchars($name, ENT_QUOTES, 'UTF-8') 进行 HTML 实体编码；移除 X-XSS-Protection: 0；不要依赖黑名单正则过滤，改用白名单或上下文编码。

**验证说明**

需在真实浏览器/代理中确认嵌套标签绕过后的实际 DOM 解析与脚本执行；不同浏览器对畸形标签的容错解析可能略有差异。
模型 POC 要点：向 name 参数注入不含字面 script 的 HTML 事件处理器，或使用嵌套 script 标签绕过黑名单，使响应中回显可执行脚本。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
AWVS 外部佐证：Cross-site Scripting (XSS) @ http://127.0.0.1:18081/052.php（未在本管线执行扫描）。
PocWriter 建议（未采纳，缺少端点 /052.php）：符合 CWE-79（跨站脚本）。漏洞位于 052.php:11，外部输入来自查询参数 name，source→sink 链在给定代码片段内静态闭合，未见有效输出编码/净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。若需脚本化复现，仅保留单条只读 GET 请求，禁止管道执行（如 curl|sh）与任何破坏性操作；TARGET 需由授权测试人员手动替换。

**外部佐证**

- awvs: Cross-site Scripting (XSS) @ http://127.0.0.1:18081/052.php

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
| `LLM-4be6b4e0336a` | Cross-site Scripting (XSS) | http://127.0.0.1:18081/052.php | corroborated |

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
| `csp` | CWE-693 |  | 0 |
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 4.69 | 是 |
| surface_mapper | 攻击面测绘 | 7.04 | 是 |
| deep_finder | LLM 深挖 | 9.48 | 是 |
| candidate_screener | 候选筛选 | 3.83 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.1 | 是 |
| coordinator | 管线协调 | 5.64 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
