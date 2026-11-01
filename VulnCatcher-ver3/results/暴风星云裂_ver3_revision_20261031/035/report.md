# 落日二号乙漏洞挖掘报告 — 20261031-012000-9d67cd

- 生成时间：2026-10-30T17:20:39.274244+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\035.zip`
- 输入模式：`zip`
- SHA256：`26df21081a34ea6645ed0ec14c03a18413f379ea7d2f67f50d3952249217e9b6`
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

本次汇总仅含 1 条已去重 finding：LLM-17fe713500f4，类型 open_redirect（medium），位于单文件 PHP 脚本 035.php 第 3-4 行，GET 参数 redirect 直接用于跳转，已附 POC（HTTP 型，可动态复现，仅限授权测试）。最高危即该条开放重定向，风险等级 medium，无高危/严重项。POC 齐全度：1/1 有 POC，但均为文本工件，未执行、未做动态验证。整体攻击面极小（1 文件、13 行、221 字节、无框架无路由），覆盖有限，多项配置/实现类风险因缺少代码内容无法排除，已转入人工复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 310 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 035.php（13 行，已全量通读）。该脚本为开放重定向：第 3 行读取 $_GET['redirect']，第 4 行直接拼入 Location 头，无任何校验，链完整闭合，已作为 medium 级 open_redirect 报告。其余线索：文件中无 SQL/命令/文件/反序列化/模板等 sink；无 md5/sha1 等弱哈希调用；无 setcookie/session 设置，故 weak_hash/insecure_cookie/weak_random 不成立；无硬编码凭据；未使用 X-Forwarded-For 等客户端头，trust_boundary 无线索。surface_notes 中提到的 Java 形态（getParameterNames、Runtime.exec 环境数组等）不适用于本 PHP 单文件。未覆盖范围：无部署配置、无路由/访问控制信息、无依赖清单，无法确认该脚本的实际 URL 路径与是否公网暴露；code_pack 之外文件视为不存在。

未覆盖 / 证据缺口：
- 缺少 Web 服务器/PHP 版本与部署配置，无法确认入口可达性与 header 处理细节
- 无端点清单，无法确认实际访问路径与访问控制
- 无依赖清单，未评估第三方组件
- 未覆盖 code_pack 之外的文件

## 3. Findings

### F-1: 035.php 通过 GET 参数 redirect 造成开放重定向

- **类型**：`open_redirect` / CWE-601
- **严重度**：`medium`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`035.php:3-4`
- **来源**：`llm_finding`

**描述**

035.php 第 3 行从 $_GET['redirect'] 读取外部输入，仅判断其非空（!= ""），未做任何白名单、协议校验或域名限制；第 4 行直接将该值拼接进 header("location: " . $_GET['redirect'])。攻击者可构造 redirect 指向任意外部站点或 javascript:/data: 等伪协议，使服务端返回 302 跳转，用于钓鱼、OAuth 令牌窃取或绕过基于域名的信任校验。

**source / sink**

- source：query `redirect`（035.php:3）
- sink：035.php:4 header("location: " . $_GET['redirect']) 响应头注入/重定向

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `035.php:3` | 从 $_GET 读取 redirect 参数，仅校验存在且非空字符串 | 攻击者完全可控的原始字符串 | 仅 != "" 判空，无协议/域名白名单 |
| 2 | `035.php:4` | 将未过滤的 redirect 值拼接进 Location 响应头并 exit | 原样拼接到 header 值 | 无 URL 解析、无 host 校验、无 CRLF 过滤 |

**POC**

针对 /035.php（GET）的 开放重定向 POC。注入点：GET 参数 redirect；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/035.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 开放重定向 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/035.php?redirect=%2F%2Fexample.com'
```
预期：响应 30x 且 Location 指向攻击者控制的域名。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`//example.com`
- POC 目录：`poc/LLM-17fe713500f4`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

开放重定向：可用于钓鱼跳转、OAuth/SSO 回调令牌窃取、绕过依赖域名的访问控制；若 PHP 版本对 header 中的 CRLF 处理不当还可能引发响应头注入。

**CVE / CWE 论证**

CWE-601 URL 重定向到不可信站点。入口匿名可达（无认证代码），source→sink 链在 035.php:3-4 完整闭合，无需特殊配置。

**修复建议**

对 redirect 目标做严格白名单：仅允许相对路径或以受信域名开头的绝对 URL；解析后校验 scheme 属于 http/https 且 host 在允许列表内，拒绝 javascript:/data: 等伪协议，并对值做 CRLF 过滤。

**验证说明**

需动态确认 Web 服务器/PHP 是否原样输出 Location 头（部分环境会对 header 值做处理），以及是否存在前置反向代理改写跳转。
模型 POC 要点：请求带 redirect 参数的 URL，服务端返回 302 跳转到攻击者站点
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /035.php）：针对 035.php 第 4 行开放重定向（CWE-601）的 POC。注入点为 GET 查询参数 redirect，其值被直接用于跳转目标（Location 头或等价跳转），未做白名单/同源校验。payload 使用 //example.com 形式（协议相对 URL），可绕过仅检查是否以 http 开头的简单过滤。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /035.php）：符合 CWE-601（URL 重定向到不可信站点）。漏洞位于 035.php:4，外部输入来自查询参数 redirect，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅文本工件，不执行、不联网。request.http 中 Content-Length 与 body 长度需按实际编码核对；示例使用 %2F%2Fexample.com（26 字节）。实际测试请将 example.com 替换为授权范围内的受控域名，TARGET 保持占位符。

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
| safety_guard | 安全防护 | 2.5 | 是 |
| surface_mapper | 攻击面测绘 | 7.75 | 是 |
| deep_finder | LLM 深挖 | 7.26 | 是 |
| candidate_screener | 候选筛选 | 2.76 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.49 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.84 | 是 |
| coordinator | 管线协调 | 5.28 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
