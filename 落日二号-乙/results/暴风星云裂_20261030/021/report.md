# 落日二号乙漏洞挖掘报告 — 20261030-224737-5baf7d

- 生成时间：2026-10-30T14:48:12.170556+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\021.zip`
- 输入模式：`zip`
- SHA256：`ff9631d6e9310b5ffe2f51550d4a9e5b12c4e83ee69a263543f6be3776889254`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`high`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总仅覆盖单文件 PHP 脚本 021.php（25 行），共 1 条去重后 finding：LLM-cd298cc9bb86，类型 xss，严重度 high，位于 021.php 第 18 行附近，POST 参数经 include 未编码直接拼接进页面，形成反射型 XSS，且 CSP nonce 硬编码可被绕过。该条为本次最高危项，且已附带 POC（has_poc=true），但 POC 属静态构造文本，未经动态验证。除此之外无其他类型 finding 交付；配置类（weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary）与注入类（command_injection / sql_injection / path_traversal）均未形成 finding，属未交付而非已排除，需按档位与人工复核处理。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 877 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 021.php（25 行）。发现 1 条闭合链：POST 参数 include 未编码拼接进 $page['body'] 导致反射型 XSS，且第 3 行 CSP nonce 硬编码、第 8 行关闭 X-XSS-Protection，使 CSP 可被绕过。未发现命令执行、SQL 注入、文件包含/路径穿越、反序列化等 sink（文件中无 system/exec/include 变量/mysqli 等调用）。配置类线索：硬编码 CSP nonce（021.php:3）已并入 XSS finding；未发现 md5/sha1/rand/setcookie 等弱实现。缺口：code_pack 未显示 $page['body'] 的最终输出语句（第 25 行后无内容），无法 100% 确认输出点，但表单拼接进 body 强烈表明其为正文输出；无端点清单、无部署配置，无法确认访问路径与认证要求。

未覆盖 / 证据缺口：
- $page['body'] 的最终 echo/print 输出语句未在 code_pack 中显示（文件止于第 25 行）
- 无端点/路由与部署配置，无法确认 021.php 访问路径、请求方法与认证要求
- 无 php.ini/Web 服务器配置，无法确认 display_errors、register_globals 等运行基线

## 3. Findings

### F-1: 021.php POST 参数 include 未编码直接拼接进页面导致反射型 XSS（CSP nonce 硬编码可绕过）

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`021.php:14-18`
- **来源**：`llm_finding`

**描述**

021.php 第 14-18 行读取 $_POST['include']，未做任何 HTML 实体编码或过滤，直接以字符串拼接方式追加到 $page['body']，随后该变量被输出到响应页面（第 19-25 行继续拼接表单 HTML，说明 $page['body'] 为页面正文输出内容）。攻击者可提交含 <script> 或事件处理器的 payload 实现反射型 XSS。同时第 3 行 CSP 使用硬编码 nonce 'TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA='，且第 8 行显式设置 X-XSS-Protection: 0 关闭浏览器 XSS 过滤，攻击者可直接在 payload 中复用该已知 nonce 的 <script nonce=...> 标签绕过 CSP 执行脚本。

**source / sink**

- source：body `include`（021.php）
- sink：021.php:18 $page['body'] .= "\n\t" . $_POST['include'] . "\n"; 拼接后输出到 HTML 响应正文

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `021.php:14` | 检测到 POST 参数 include 存在 | 原始用户输入 $_POST['include'] |  |
| 2 | `021.php:15-17` | 将 include 值直接字符串拼接到 $page['body']，无 htmlspecialchars/实体编码/白名单 | 未编码的 HTML 片段进入页面正文变量 |  |
| 3 | `021.php:19-25` | $page['body'] 继续拼接表单并作为页面正文输出，注入的标签随响应返回浏览器解析 | 浏览器解析执行注入的脚本 |  |

**POC**

针对 /021.php（POST）的反射型跨站脚本（XSS）POC。注入点为 POST 表单参数 include，该参数值未经 HTML 编码即被输出到响应页面，导致脚本在受害者浏览器中执行。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/021.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/021.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'include=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-cd298cc9bb86`
- 执行状态：未执行（`executed=False`）

**影响**

反射型 XSS，可在受害者浏览器上下文执行任意脚本，窃取会话/凭证、发起 CSRF 操作或钓鱼；硬编码 nonce 使 CSP 防护完全失效。

**CVE / CWE 论证**

CWE-79。外部可达（HTTP POST 参数），无需认证，source→sink 链在 021.php:14-18 完整闭合，且 021.php:3 硬编码 nonce 与 021.php:8 关闭 X-XSS-Protection 使防护可绕过。

**修复建议**

对 $_POST['include'] 使用 htmlspecialchars($v, ENT_QUOTES, 'UTF-8') 输出编码；移除硬编码 nonce，改为每次请求随机生成；移除 X-XSS-Protection: 0。

**验证说明**

需确认 $page['body'] 最终确实被 echo/print 输出到响应（code_pack 仅显示到第 25 行拼接，未见最终输出语句，但表单 HTML 拼接进 body 表明其为页面正文）；需确认 021.php 的实际访问路径与是否需认证。
模型 POC 要点：向 021.php 提交 include 参数，注入复用硬编码 nonce 的 script 标签，绕过 CSP 触发 alert。仅限授权测试。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /021.php）：符合 CWE-79（跨站脚本）。漏洞位于可交付代码 021.php 第 18 行，外部输入来自 POST body 参数 include，source→sink 链在静态审计中闭合，未发现有效输出编码/净化；具备远程触发条件，无需认证即可反射利用。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为已获授权的真实目标，并手动运行。request.http 中的 Content-Length 需按实际请求体长度校正。若响应上下文为 HTML 属性或已有脚本块，可改用 " onmouseover=alert(document.domain) 或 </script><script>alert(document.domain)</script> 等变体。禁止用于未授权目标。

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
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 4.42 | 是 |
| surface_mapper | 攻击面测绘 | 7.43 | 是 |
| deep_finder | LLM 深挖 | 7.85 | 是 |
| candidate_screener | 候选筛选 | 3.4 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.43 | 是 |
| coordinator | 管线协调 | 5.59 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
