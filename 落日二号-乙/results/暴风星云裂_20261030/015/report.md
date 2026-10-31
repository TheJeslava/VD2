# 落日二号乙漏洞挖掘报告 — 20261030-224649-b80a0d

- 生成时间：2026-10-30T14:47:29.805398+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\015.zip`
- 输入模式：`zip`
- SHA256：`24ec46248538ba08d8e8eb94c82934ecea9f754341b0de0a93fec8dda6a387c2`
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

本次审计范围仅限单文件 PHP 脚本 015.php（83 行），共交付 1 条 finding：LLM-9d59a2937bde，类型 auth_bypass，严重度 high，位于 015.php 第 69 行附近，问题为 DVWA 密码修改流程在 step=2 时直接提交 passed_captcha=true 即可跳过 CAPTCHA 校验，属于认证/校验逻辑绕过。这是本次最高危且唯一交付项，已附带 POC（HTTP 型，可针对 TARGET 复现，仅限授权测试）。POC 齐全度：1/1 交付项均有 POC。需强调：本次 min_severity=high、suppressed_count=0，但 surface_notes 中列出的注入类、路径包含类、XSS 类攻击面以及 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 等候选均未形成 finding，属于未覆盖或需人工复核，不能据此认定不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3350 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 015.php（83 行，DVWA captcha 模块片段）。发现两条链：1) step=2 分支仅信任客户端 passed_captcha 字段，可绕过 CAPTCHA 直接修改密码（auth_bypass，high）；2) password_new/password_conf 未转义回显到隐藏 input 的 value 属性（反射型 XSS，medium）。第 64 行对密码做了 mysqli_real_escape_string 后再 md5，第 68 行 SQL 中 user 来自 dvwaCurrentUser() 而非用户输入，未发现可闭合的 SQL 注入。md5 用于口令摘要属 weak_hash（CWE-328），但 DVWA 设计如此且无独立利用链，仅作线索。未覆盖：无 php.ini/路由/部署配置，无法确认实际 URL 与认证要求；recaptcha_check_answer 与 dvwaCurrentUser 定义不在 code_pack 内。

未覆盖 / 证据缺口：
- 无路由/端点元数据，endpoint 路径按 DVWA 惯例推断
- recaptcha_check_answer、dvwaCurrentUser、$GLOBALS['___mysqli_ston'] 定义不在 code_pack
- 无部署与 WAF 信息，实际可利用性需人工确认
- weak_hash(md5) 线索未单独立项

## 3. Findings

### F-1: DVWA 密码修改功能 CAPTCHA 校验可被绕过（step=2 直接提交 passed_captcha=true）

- **类型**：`auth_bypass` / CWE-287
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`015.php:46-69`
- **来源**：`llm_finding`

**描述**

脚本第 3-44 行要求 step=1 时通过 recaptcha_check_answer 校验 CAPTCHA，但第 46-81 行的 step=2 分支仅检查客户端提交的 $_POST['passed_captcha'] 是否为真值（第 55 行），并未在服务端重新验证 CAPTCHA 令牌。攻击者可直接构造 step=2 且 passed_captcha=true 的请求，跳过 CAPTCHA 校验直接修改当前用户密码。结合第 62 行仅比较两次密码一致、第 68 行直接 UPDATE users 表，构成完整的认证保护绕过链。

**source / sink**

- source：body `passed_captcha`（015.php）
- sink：015.php:69 mysqli_query 执行 UPDATE users SET password

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:46` | 攻击者直接提交 step=2 与 Change 参数，进入第二分支，跳过 step=1 的 recaptcha_check_answer 校验 | 外部 POST 参数 step=2 |  |
| 2 | `015.php:55` | 仅检查 $_POST['passed_captcha'] 是否为真值，该值完全由客户端控制 | passed_captcha=true 通过检查 | 服务端未重新校验 CAPTCHA 令牌，仅信任客户端隐藏字段 |
| 3 | `015.php:62` | 两次密码一致即进入更新逻辑 | password_new == password_conf |  |
| 4 | `015.php:65` | 对密码做 md5 摘要 | md5(password_new) |  |
| 5 | `015.php:68` | 拼接 UPDATE 语句并执行，修改当前用户密码 | SQL 语句执行 |  |

**POC**

针对 DVWA captcha 模块（POST，路径按部署推断为 /vulnerabilities/captcha/）的认证绕过 POC。源码 015.php:69 处对 POST 参数 passed_captcha 的校验可被绕过：直接提交固定值即可通过验证，无需正确解答验证码。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/captcha/ (DVWA captcha 模块，路径按部署推断)'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 认证绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/captcha/ (DVWA captcha 模块，路径按部署推断)' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'passed_captcha=admin'
```
预期：以未授权/伪造身份访问受保护资源返回 2xx。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`admin`
- POC 目录：`poc/LLM-9d59a2937bde`
- 执行状态：未执行（`executed=False`）

**影响**

攻击者无需通过 CAPTCHA 即可修改账户密码，绕过反自动化保护，可配合 CSRF 或暴力流程实现账户接管。

**CVE / CWE 论证**

CWE-804/ CWE-602 客户端安全控制绕过：passed_captcha 为客户端可控隐藏字段，服务端未做二次校验，外部低权限用户可直接触发，链闭合。

**修复建议**

在 step=2 分支服务端重新校验 CAPTCHA 令牌（或使用一次性服务端会话标记），不要信任客户端 passed_captcha 字段。

**验证说明**

需确认部署路径与 DVWA 版本；recaptcha_check_answer 返回值语义需运行时确认，但 step=2 分支完全不调用该函数，绕过逻辑与运行时无关。
模型 POC 要点：直接提交 step=2 并伪造 passed_captcha=true，绕过 CAPTCHA 修改密码
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：符合 CWE-287（Improper Authentication）。漏洞位于可交付代码 015.php:69，外部输入来自请求体参数 passed_captcha，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权目标并确认授权范围；不要对非授权目标运行。若实际部署路径不同，请按真实路由调整 URL，但注入点仍为 POST 参数 passed_captcha。

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
| `auth_bypass` | CWE-287 | 是 | 1 |
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
| safety_guard | 安全防护 | 4.59 | 是 |
| surface_mapper | 攻击面测绘 | 8.98 | 是 |
| deep_finder | LLM 深挖 | 11.27 | 是 |
| candidate_screener | 候选筛选 | 3.43 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.25 | 是 |
| coordinator | 管线协调 | 6.57 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
