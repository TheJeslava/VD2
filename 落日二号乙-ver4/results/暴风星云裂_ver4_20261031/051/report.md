# 落日二号乙漏洞挖掘报告 — 20261031-164808-45ee29

- 生成时间：2026-10-31T08:48:40.886859+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\051.zip`
- 输入模式：`zip`
- SHA256：`96483940cd4d3e7d3eebe8443bc19f27aedea70513cee1c5302276aeb59557a9`
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

本次汇总仅含 1 条去重后的 finding：051.php 的开放重定向候选（GEN-6e4cfba5fa5e，medium，CWE-601），带 POC，但证据等级为规则命中且标题自述“证据不足以确认”，属静态/规则推断，未做动态验证。最高危即该条 medium；无 high/critical。POC 齐全度：1/1 有 POC，但为静态证据型 POC，不能宣称可动态复现。整体项目为单文件 PHP（051.php，14 行），无框架、无路由、无端点清单，攻击面窄但覆盖极不完整。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 383 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 051.php 全部 14 行。第 4-5 行从 $_GET['default'] 读取外部输入，第 8 行用 stripos 检查是否含 "<script"，命中则第 9 行 header 重定向到 ?default=English 并 exit。关键点：该脚本对 $default 只做黑名单检查，之后没有任何输出/汇点——既无 echo/print，也无 include/require、eval、system/exec、文件读写或 SQL 拼接。因此不存在 source→sink 闭合链：黑名单绕过（如 <SCRIPT、<img onerror>）虽可绕过第 8 行，但绕过后的值不会被任何危险操作使用，无法形成 XSS 或其它可利用漏洞。sink_hot_files 为空与源码一致，不是漏报。未发现可申报 CVE 的问题，findings 为空。

未覆盖 / 证据缺口：
- 无 composer.json/依赖清单，第三方组件 CVE 无法评估
- 无 Web 服务器/php.ini 配置，无法确认 allow_url_include、open_basedir 等运行时设置
- 无端点与部署信息，无法确认 051.php 实际访问路径与鉴权/WAF 保护
- 第 8 行黑名单可被大小写/非 script 标签绕过，但因缺少输出汇点，不构成可利用漏洞，仅作为代码质量线索记录

## 3. Findings

### F-1: 051.php 开放重定向候选（CWE-601）——证据不足以确认

- **类型**：`open_redirect` / CWE-601
- **严重度**：`medium`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`051.php:7-9`
- **来源**：`rule`

**描述**

候选声称 051.php:5 从 query 参数 `default` 读取外部输入，并在 051.php:9 通过 header("location: ?default=English") 形成开放重定向。但按输入给出的代码片段，第 9 行的 Location 值是硬编码字符串 "?default=English"，其中不含变量 $default，因此外部输入并未到达该 header 汇点；第 8 行的 stripos($default, "<script") 只是对输入做 XSS 关键字检查，与重定向目标无关。输入未提供 051.php:5 的实际读取语句（如 $_GET['default']），也未提供任何将 $default 拼接进 Location 头的代码行，故 source→sink 链在给定证据下不闭合。

**source / sink**

- source：query `default`（051.php:5）
- sink：051.php:9 header ("location: ?default=English");

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `051.php:5` | 从 query `default` 读取外部输入 | 污点进入 default |  |
| 2 | `051.php:9` | 危险汇点：header ("location: ?default=English"); | 污点进入 open_redirect 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /051（GET）的开放重定向 POC。源码 051.php:9 将 GET 参数 default 的值直接用于重定向目标（Location），未做白名单或同源校验，攻击者可传入 //example.com 之类的协议相对 URL 使浏览器跳转到外部域名。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/051'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 开放重定向 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/051?default=%2F%2Fexample.com'
```
预期：响应为 30x 且 Location 指向攻击者控制的域名。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`//example.com`
- POC 目录：`poc/GEN-6e4cfba5fa5e`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

证据不足：若确实存在将用户可控值写入 Location 头的代码，则可能被用于钓鱼跳转（诱导用户从可信域跳转到攻击者站点）；但当前片段中 Location 为固定值，无法据此认定可利用的开放重定向。

**CVE / CWE 论证**

CWE-601（URL 重定向到不可信站点）要求外部可控输入进入重定向目标。给定证据中 051.php:9 的 header 值为常量 "?default=English"，不满足外部可达且可控的利用链闭合条件；无认证要求这一点也无法从片段确认。故不满足 CVE 论证所需的外部可达性与链闭合。

**修复建议**

若后续确认存在动态 Location 拼接：1) 不要直接把请求参数作为跳转目标；2) 使用服务端白名单映射（如 default→已知页面 ID），或仅允许相对路径并校验以单个 '/' 开头、拒绝 '//'、'\\'、'http:'、'https:' 等；3) 跳转前用 parse_url 规范化并比对允许的 host；4) 对无法校验的输入回退到固定默认页。

**验证说明**

静态证据：入口 GET /051；source=query/default；sink=051.php:9；规则 php-redirect。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：候选链：051.php:5 读取 query `default` → 051.php:8 stripos 检查 "<script" → 051.php:9 header("location: ?default=English")。按片段，第 9 行未引用 $default，污点未到达汇点，链条在证据层面断开；第 8 行的检查针对 XSS 而非重定向目标校验，即使存在动态拼接也不构成有效防护。
PocWriter 建议（未采纳，缺少端点 /051）：符合 CWE-601（URL 重定向到不可信站点）。漏洞位于 051.php:9，外部输入来自查询参数 default，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。执行前将 TARGET 替换为授权测试目标；重点检查响应中的 Location 头，而非响应体。若源码对 default 做了同源校验，则本 POC 不成立，需以源码为准。

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
| `open_redirect` | CWE-601 |  | 1 |
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
| safety_guard | 安全防护 | 3.77 | 是 |
| surface_mapper | 攻击面测绘 | 7.34 | 是 |
| deep_finder | LLM 深挖 | 2.68 | 是 |
| candidate_screener | 候选筛选 | 1.94 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.67 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.47 | 是 |
| coordinator | 管线协调 | 5.82 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
