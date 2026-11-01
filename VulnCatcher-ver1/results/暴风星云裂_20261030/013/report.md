# 落日二号乙漏洞挖掘报告 — 20261030-224638-0d305a

- 生成时间：2026-10-30T14:47:16.984939+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\013.zip`
- 输入模式：`zip`
- SHA256：`c79a98517aa6ef490facce4e07350a32f2516ff99bcb58570c7b55f84a352bbe`
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

本次汇总仅含 1 条已去重 finding：LLM-a618508f9b61，类型 auth_bypass（高危），位于单文件 PHP 脚本 013.php 第 23 行附近，声称 DVWA 密码修改接口的 CAPTCHA 校验可通过伪造 g-recaptcha-response=hidd3n_valu3 与 User-Agent=reCAPTCHA 绕过，且已附带 POC（属 HTTP 型 POC，但仅为静态文本工件，未做动态验证）。最高危即此条 auth_bypass。POC 齐全度为 1/1（with_poc=1），但证据等级为 llm_inferred，需人工复核。攻击面测绘提出的 source(013.php:6)→sink(013.php:1) 注入链、文件/路径操作、命令执行、弱哈希/弱随机/Cookie 标志等风险点，均未被任何 finding 覆盖，已转入 human_review。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2150 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计唯一文件 013.php（1-55 行，DVWA 密码修改页面）。发现两条链：(1) 高危 CAPTCHA 绕过——第 17-23 行硬编码后门分支 g-recaptcha-response=='hidd3n_valu3' 且 User-Agent=='reCAPTCHA' 即可跳过人机校验进入改密，攻击者完全可控，链闭合；(2) 中危弱哈希——第 27 行无盐 md5 存储口令。第 30-31 行 SQL 使用 mysqli_real_escape_string 转义且 user 来自 dvwaCurrentUser()，未发现可闭合的 SQL 注入；第 53 行 generateSessionToken() 生成 token 但本流程未校验，存在 CSRF 隐患，因缺少 token 校验代码与端点上下文，未单独立项。未提供 php.ini/部署配置，无法确认 recaptcha 私钥是否配置（影响后门分支是否为唯一通过路径）。

未覆盖 / 证据缺口：
- 无 php.ini/Web 服务器配置，无法确认 allow_url_include、open_basedir 等
- 无端点清单，无法确认脚本是否对外暴露及是否位于认证之后
- generateSessionToken() 定义不在 code_pack，CSRF 校验缺失无法完全确认
- recaptcha 私钥是否配置未知，影响 CAPTCHA 绕过路径的实际必要性

## 3. Findings

### F-1: DVWA 密码修改接口 CAPTCHA 校验可被伪造请求头绕过（g-recaptcha-response=hidd3n_valu3 + User-Agent=reCAPTCHA）

- **类型**：`auth_bypass` / CWE-287
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`013.php:17-23`
- **来源**：`llm_finding`

**描述**

013.php 的密码修改逻辑在 recaptcha_check_answer 返回假值后，仍存在一条硬编码后门分支：只要 POST 参数 g-recaptcha-response 等于固定字符串 'hidd3n_valu3' 且 HTTP User-Agent 头等于 'reCAPTCHA'，条件即为真，直接进入密码修改流程。这两个值完全由攻击者控制（一个在请求体、一个在请求头），无需真实通过 reCAPTCHA 人机校验，即可在无有效 CAPTCHA 的情况下修改当前登录用户的密码，构成认证/人机校验绕过（CWE-287 / CWE-804）。

**source / sink**

- source：body `g-recaptcha-response`（013.php）
- sink：013.php:23 013.php:25-31 密码一致性校验通过后执行 UPDATE users SET password=md5(...) 修改账户口令

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:3` | 入口判断 POST 参数 Change 是否存在，存在即进入密码修改流程 | 攻击者提交 POST 表单，Change 置位 |  |
| 2 | `013.php:12-15` | 调用 recaptcha_check_answer 校验第三方 CAPTCHA，返回值 $resp 通常为 false（未通过或未配置密钥） | $resp = false |  |
| 3 | `013.php:17-23` | 短路分支：$resp 为假时进入硬编码后门判断，g-recaptcha-response=='hidd3n_valu3' 且 User-Agent=='reCAPTCHA' 时整体条件为真 | 攻击者可控的两个值命中硬编码常量，条件恒真 | 绕过真实 reCAPTCHA 人机校验，使用硬编码魔法值与可伪造的 User-Agent 头 |
| 4 | `013.php:25-31` | 两次新密码一致后经 mysqli_real_escape_string 与 md5 处理，拼接 UPDATE 语句修改当前用户密码 | password_new 经转义与 md5 后写入 SQL |  |

**POC**

针对 /013.php（POST）的认证绕过 POC。注入点为 POST 参数 g-recaptcha-response，源码在 013.php:23 附近将该参数用于验证码/认证判定，未做有效校验即可通过。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/013.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 认证绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/013.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'g-recaptcha-response=admin'
```
预期：以未授权/伪造身份访问受保护资源返回 2xx。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`admin`
- POC 目录：`poc/LLM-a618508f9b61`
- 执行状态：未执行（`executed=False`）

**影响**

攻击者无需通过人机校验即可修改账户密码；若配合 CSRF（脚本第 53 行仅生成 token 但本流程未校验 token），可诱导受害者改密导致账户接管。

**CVE / CWE 论证**

CWE-287 认证绕过 / CWE-804 可猜测/硬编码凭证：外部 HTTP 可达，攻击者完全控制触发条件（请求体参数 + 请求头），无需真实 CAPTCHA，链闭合。

**修复建议**

移除硬编码的 'hidd3n_valu3'/'reCAPTCHA' 后门分支，仅以 recaptcha_check_answer 的真实返回值为准；同时在本流程中校验 CSRF token。

**验证说明**

需确认部署环境是否配置了 recaptcha 私钥（未配置时 $resp 恒假，后门分支成为唯一通过路径，危害更大）；需确认 dvwaCurrentUser() 返回的会话用户身份。
模型 POC 要点：携带伪造的 g-recaptcha-response 与 User-Agent 头提交密码修改请求，绕过 CAPTCHA 直接改密
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /013.php）：符合 CWE-287（Improper Authentication）。漏洞位于可交付代码 013.php:23，外部输入来自 POST body 参数 g-recaptcha-response，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。脚本中的 TARGET 需由授权测试人员手动替换；请勿使用 curl|sh 等自动执行方式。request.http 中的 Content-Length 需按实际 body 长度调整（g-recaptcha-response=admin 为 26 字节）。

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
| safety_guard | 安全防护 | 4.02 | 是 |
| surface_mapper | 攻击面测绘 | 8.39 | 是 |
| deep_finder | LLM 深挖 | 12.32 | 是 |
| candidate_screener | 候选筛选 | 3.0 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.27 | 是 |
| coordinator | 管线协调 | 6.36 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
