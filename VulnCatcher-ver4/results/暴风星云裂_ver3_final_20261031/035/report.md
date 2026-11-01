# 落日二号乙漏洞挖掘报告 — 20261031-014156-c2624d

- 生成时间：2026-10-30T17:42:35.872740+00:00
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

本次汇总仅含 1 条已去重 finding：035.php 第 5 行将 GET 参数 redirect 未校验写入 Location 头，构成开放重定向（open_redirect，medium，LLM-5ea158bc397a），已附带 POC，属 HTTP 型可复现文本工件（未执行、未动态验证）。最高危即该条 medium 开放重定向；除此之外无其他类型交付。需强调：surface_notes 明确指出 sink_hot_files 为空、未提供 035.php 逐行代码内容、无端点/路由清单，因此第 3 行外部输入到汇点的完整链路未被自动识别，weak_hash/weak_random/weak_crypto/insecure_cookie/trust_boundary 等候选均停留在人工复核清单，不能视为已排除。POC 齐全度：1/1 条 finding 带 POC，但均为静态构造文本，未做动态验证。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 310 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 035.php（13 行），已逐行审计。第 3 行读取 $_GET['redirect']，第 4 行直接拼入 header("location: ...")，构成完整的开放重定向（CWE-601）链路，已作为唯一 finding 交付。文件中未出现 SQL、文件包含、命令执行、反序列化、模板、SSRF、弱哈希/弱随机/弱加密、setcookie 标志位或信任 X-Forwarded-* 等其它汇点；surface_notes 中列出的 weak_hash/weak_random/weak_crypto/insecure_cookie/trust_boundary 候选在可见代码中均无对应实现，故不报告。未闭合线索：无 endpoints 清单与部署信息，无法确认脚本是否公网可达及实际 URL 路径；无 php.ini/服务器配置，无法判断 header 是否受 output_buffering 影响。code_pack 之外文件视为不存在，未覆盖。

未覆盖 / 证据缺口：
- 无 HTTP 端点/路由清单，endpoint 字段按文件名推断为 /035.php，需人工确认实际访问路径
- 无部署方式与 Web 服务器配置，无法确认脚本是否对外暴露及 header 发送条件
- 无 php.ini，无法确认 output_buffering/错误显示等运行基线
- 仓库仅 1 个文件，无依赖与版本历史，无法关联已知 CVE 样本

## 3. Findings

### F-1: 035.php 通过 GET 参数 redirect 未校验即写入 Location 头导致开放重定向

- **类型**：`open_redirect` / CWE-601
- **严重度**：`medium`
- **置信度**：`0.82`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`035.php:3-5`
- **来源**：`llm_finding`

**描述**

脚本在第 3 行读取 $_GET['redirect']，仅判断其存在且非空字符串，第 4 行直接拼接进 header("location: " . $_GET['redirect'])。代码未做任何白名单、同源校验、scheme/host 校验或相对路径限制，攻击者可传入任意外部 URL（如 https://evil.example/），使服务端返回 302 跳转至攻击者站点。可用于钓鱼、OAuth/SSO 回调欺骗、绕过基于域名的信任判断。

**source / sink**

- source：query `redirect`（035.php）
- sink：035.php:5 header("location: " . $_GET['redirect']) 第 4 行，直接设置 HTTP 重定向响应头

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `035.php:3` | array_key_exists("redirect", $_GET) 与 $_GET['redirect'] != "" 仅校验参数存在且非空，未做任何内容校验 | 攻击者完全可控的原始字符串 |  |
| 2 | `035.php:4` | 将参数值直接字符串拼接到 header("location: " . ...) 并发送，随后 exit | 未编码、未校验的外部 URL 进入 Location 响应头 | 不存在白名单/同源/scheme 校验，任何以非空字符串形式提供的绝对 URL 均被接受 |

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
- POC 目录：`poc/LLM-5ea158bc397a`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可构造指向自身站点的可信域名链接（TARGET/035.php?redirect=...），诱导用户点击后跳转至钓鱼页面或恶意站点，可用于凭据窃取、OAuth 授权码劫持等场景。

**CVE / CWE 论证**

CWE-601 URL Redirection to Untrusted Site（Open Redirect）。入口为匿名可达的 GET 参数，无认证要求，source→sink 链路在 035.php:3-4 完整闭合，无需运行时特殊条件即可触发。

**修复建议**

对 redirect 目标做严格校验：仅允许站内相对路径（拒绝包含 scheme 或 // 的值），或使用服务端维护的允许跳转目标白名单映射；必要时对输出值做 URL 解析后校验 host 与 scheme 属于可信集合。

**验证说明**

需确认 035.php 在目标环境中的实际可访问路径与是否被 Web 服务器直接暴露；需确认无前置输出导致 header 发送失败。开放重定向通常按中危处理，赏金平台接受度视项目策略而定。
模型 POC 要点：向脚本传入外部域名作为 redirect 参数，观察服务端返回 302 且 Location 指向攻击者站点
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /035.php）：针对 035.php（GET）的开放重定向（CWE-601）POC。注入点为 GET 参数 redirect，其值被直接用于跳转目标（035.php:5），未做白名单/同源校验。payload 使用 //example.com 触发协议相对跳转，目标地址统一使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /035.php）：漏洞位于可交付代码 035.php:5，外部输入来自 GET 参数 redirect，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标，勿使用真实域名。

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
| safety_guard | 安全防护 | 2.75 | 是 |
| surface_mapper | 攻击面测绘 | 8.71 | 是 |
| deep_finder | LLM 深挖 | 7.66 | 是 |
| candidate_screener | 候选筛选 | 2.26 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.03 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.64 | 是 |
| coordinator | 管线协调 | 6.19 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
