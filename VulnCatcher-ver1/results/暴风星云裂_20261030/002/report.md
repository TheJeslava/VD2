# 落日二号乙漏洞挖掘报告 — 20261030-224520-825565

- 生成时间：2026-10-30T14:45:44.607050+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\002.zip`
- 输入模式：`zip`
- SHA256：`e1763d6f3dacb5f1144d8bf313ac2128337f0729a834123f8f766fea9b793fc2`
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

本次汇总的 findings 为空：已去重清单中没有任何已确认漏洞，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。攻击面测绘只覆盖 1 个 PHP 文件（002.php，121 行，约 3KB），没有框架、没有路由清单、没有端点声明，也没有提供源码正文；source 热点在第 2 行、sink 热点在第 4 行，属于基于行号的推断，不构成漏洞结论。最高危的候选方向是文件前段参数接收后直接流入危险汇点（命令执行、代码执行、文件包含、注入类），但当前没有任何一条被落地为具体行号与变量，因此不能宣称存在高危漏洞，也不能宣称不存在。POC 不齐全：0 条 finding 对应 0 个 POC。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3749 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 002.php（1-121 行，未截断）。该文件是一个纯前端展示页：第 6-7 行的 POST 分支为空；第 9-10 行读取 $_SERVER['REQUEST_URI'] 并仅做 str_replace 去掉 "/vulnerabilities/api/" 前缀，结果 $stripped_url 在第 47 行被拼进内联 <script> 的字符串常量（const url = '.../vulnerabilities/api/v2/user/'），随后第 49 行 fetch 该 URL。这是本文件中唯一从请求到输出的数据流。<br><br>未将其作为 finding 交付的原因：<br>1) 反射型 XSS 需要闭合单引号并注入脚本，但 REQUEST_URI 在 PHP 中通常已被 URL 编码，且该页面无认证/会话证据，无法证明可窃取管理员会话或触发敏感操作，达不到 min_severity=high 的 CVE 级门槛；<br>2) 该拼接只影响客户端 fetch 的目标地址，服务端不据此发起请求，不构成 SSRF；<br>3) 第 12-119 行其余内容均为静态 HTML/JS 字符串，第 34、81、94 行使用 innerHTML 渲染的是后端 API 返回的 user_json 字段，属于另一个（未在 code_pack 中的）API 端点的输出，本文件内无该数据的服务端来源，链不闭合；<br>4) 文件中未出现 system/exec/shell_exec/passthru、mysqli_query、include/require、file_get_contents/fopen、unserialize、extract/parse_str、setcookie、md5/sha1/rand 等任何危险汇点或弱实现，配置型候选（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）均无证据。<br><br>未闭合线索：第 47 行 $stripped_url 的反射若在特定部署下 REQUEST_URI 未被编码，可能形成反射型 XSS，建议人工确认 Web 服务器对 URI 的规范化行为；第 94 行 cell.innerHTML = value 的存储型 XSS 取决于 /vulnerabilities/api/v2/user/ 接口返回内容，该接口源码不在 code_pack 中，无法评估。输入中未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- /vulnerabilities/api/v2/user/ 接口的服务端实现未提供，无法评估第 94 行 innerHTML 渲染的存储型 XSS 与第 39 行 id==2 && level==0 的越权判断
- 无 php.ini / Web 服务器配置，无法确认 REQUEST_URI 编码与 allow_url_include 等开关
- 无认证/会话文件，无法确认该页面是否受鉴权保护
- 无数据库与外部服务配置，SQL 注入与 SSRF 可达性无法评估

## 3. Findings

未发现满足阈值的候选。

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
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.95 | 是 |
| surface_mapper | 攻击面测绘 | 9.39 | 是 |
| deep_finder | LLM 深挖 | 4.81 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 6.07 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
