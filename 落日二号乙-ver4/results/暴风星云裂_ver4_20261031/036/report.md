# 落日二号乙漏洞挖掘报告 — 20261031-164523-c1ae0e

- 生成时间：2026-10-31T08:46:05.861535+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\036.zip`
- 输入模式：`zip`
- SHA256：`21f0b55e102a19f7e1305cfce872a6ab1e1c931079a8ad1e4b9dbafe94f87b7f`
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

本次汇总仅含 1 条已去重 finding：036.php 第 13 行附近的开放重定向（open_redirect，medium，LLM-7af8cc31bcdd），通过 redirect 参数的黑名单绕过实现，已附带 POC（HTTP 型，可动态复现，仅限授权测试）。这是本次唯一交付项，也是最高危项。除此之外没有其他类型 finding，POC 齐全度按已交付项计为 1/1。需强调：输入未提供 036.php 源码正文，仅提供文件清单与热点行号（第 4 行为输入热点），sink_hot_files 为空，因此注入类、配置类风险均无法从代码层面确认，不能据此判定不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 524 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 036.php（21 行），已通读全文。唯一外部输入为 $_GET['redirect']（036.php:3），其数据流经 036.php:4 的黑名单正则后于 036.php:11 进入 header("location: ...")，构成可绕过的开放重定向（CWE-601），已作为 medium 候选交付。文件中未发现 exec/system/passthru、数据库查询、include/require、文件读写、反序列化、SSRF 或模板渲染等其它汇点；也未发现 md5/sha1、rand/mt_rand、mcrypt/openssl、setcookie 等配置类风险代码。surface_notes 中提到的 weak_hash/weak_random/weak_crypto/insecure_cookie/trust_boundary 在可见源码中均无对应实现，故不单独立项。未覆盖范围：无 php.ini/Web 服务器配置、无路由与部署信息，无法确认脚本可达路径与运行环境；这些缺口不影响上述开放重定向链的闭合判断。

未覆盖 / 证据缺口：
- 缺少 php.ini/Web 服务器配置，无法确认 allow_url_include、display_errors 等设置
- 无端点清单与部署信息，无法确认 036.php 的实际可达路径与 HTTP 方法
- 无依赖清单，第三方库风险未覆盖
- 开放重定向的实际可利用性依赖客户端对 Location 头的处理，需动态验证

## 3. Findings

### F-1: 036.php 通过 redirect 参数的黑名单绕过导致开放重定向

- **类型**：`open_redirect` / CWE-601
- **严重度**：`medium`
- **置信度**：`0.82`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`036.php:3-13`
- **来源**：`llm_finding`

**描述**

脚本从 $_GET['redirect'] 读取跳转目标，仅用正则 /http:\/\/|https:\/\//i 拦截以 http:// 或 https:// 开头的绝对 URL，随后直接拼接到 header("location: " . $_GET['redirect'])。该黑名单只匹配字面量协议前缀，未做协议白名单、未解析 URL、未限制为相对路径，因此可用协议相对形式 //evil.example、大小写/编码变体、或其它 scheme（如 javascript:、data:、ftp:）绕过，把用户重定向到攻击者控制的站点，用于钓鱼或 OAuth/SSO 令牌窃取。

**source / sink**

- source：query `redirect`（036.php）
- sink：036.php:13 header("location: " . $_GET['redirect']) 位于 036.php:11

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `036.php:3` | 检查 $_GET['redirect'] 存在且非空，攻击者完全控制该值 | 原始攻击者字符串 |  |
| 2 | `036.php:4` | preg_match 仅拦截包含 http:// 或 https:// 的值；协议相对 //host 或 javascript:/data: 等不含该子串，校验通过 | 未被拦截的攻击者字符串 | 黑名单只匹配 http:// 与 https:// 字面量，//evil.example、javascript:、data:、ftp: 等均不命中 |
| 3 | `036.php:11` | 未规范化的值直接拼入 Location 响应头并 exit | 原样写入响应头 |  |

**POC**

针对 /036.php（GET）的 开放重定向 POC。注入点：GET 参数 redirect；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/036.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 开放重定向 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/036.php?redirect=%2F%2Fexample.com'
```
预期：响应为 30x 且 Location 指向攻击者控制的域名。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`//example.com`
- POC 目录：`poc/LLM-7af8cc31bcdd`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可构造可信域下的链接将用户重定向至恶意站点，用于钓鱼、凭据窃取或配合 OAuth 回调劫持令牌。

**CVE / CWE 论证**

CWE-601 URL Redirection to Untrusted Site。无需认证，外部可直接通过 GET 参数触发，source→sink 链在 036.php:3-11 完整闭合，黑名单可被协议相对 URL 绕过。

**修复建议**

不要直接使用用户输入作为跳转目标；改为服务端维护的允许列表映射（如 redirect=home→/home），或仅允许以单个 / 开头的站内相对路径并拒绝 //、\、: 等字符，同时校验解析后的 host 与本站一致。

**验证说明**

需动态确认 Web 服务器/PHP 是否原样输出 Location 头（部分环境会对 // 做处理），以及客户端是否跟随协议相对跳转；javascript: 伪协议的实际效果依赖客户端。
模型 POC 要点：利用协议相对 URL 绕过绝对 URL 黑名单，触发 302 跳转到攻击者站点
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /036.php）：针对 036.php 第 13 行的开放重定向（CWE-601）。外部输入来自 GET 查询参数 redirect，未经有效校验即用于跳转目标，攻击者可构造指向外部站点的 30x 跳转。POC 仅使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /036.php）：符合 CWE-601（URL 重定向至不可信站点）。漏洞位于 036.php:13，外部输入来自查询参数 redirect，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。执行前将 TARGET 替换为授权测试目标；重点检查响应中的 Location 头，而非响应体。

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
| safety_guard | 安全防护 | 3.07 | 是 |
| surface_mapper | 攻击面测绘 | 7.8 | 是 |
| deep_finder | LLM 深挖 | 8.15 | 是 |
| candidate_screener | 候选筛选 | 3.42 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.79 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.47 | 是 |
| coordinator | 管线协调 | 5.18 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
