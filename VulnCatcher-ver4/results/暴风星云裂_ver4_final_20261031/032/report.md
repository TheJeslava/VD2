# 落日二号乙漏洞挖掘报告 — 20261031-173026-0aaa2e

- 生成时间：2026-10-31T09:31:01.715848+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\032.zip`
- 输入模式：`zip`
- SHA256：`00f20c6c4951b7689cab1e0be3d0e1d93bb7cb42b3399af954133774b6e161fd`
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

本次审计对象为单文件 PHP 脚本 032.php（24 行，约 4.2KB），无框架、无路由清单、无 source/sink 热点标注。去重后仅交付 1 条 finding：SEM-991eb6123bf3（weak_crypto，medium），标题为「客户端令牌生成使用 MD5 弱哈希」，定位 032.php 第 18 行，来源为规则命中，已附带 POC。需注意该条标题写 weak_crypto，但描述与 CWE-328 属弱哈希（weak_hash）语义，存在类型标注不一致，建议人工按 CWE-328 归类复核。最高危即此条 medium；本次无 high/critical 交付项。POC 齐全度为 1/1，但该 POC 属静态证据型（算法/常量层面），不具备 HTTP 动态复现条件，不能宣称可动态验证。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 4350 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单个 PHP 文件 032.php（24 行），已全量逐行审计。文件内容为：第 1 行 <?php 开始，第 2-23 行通过 heredoc 向 $page['body'] 追加一段纯前端 JavaScript（blueimp JavaScript-MD5 库、rot13 函数、generate_token 函数），第 24 行结束 PHP 标签。服务端侧不存在任何外部输入读取（无 $_GET/$_POST/$_COOKIE/$_REQUEST/$_SERVER/$_FILES）、无命令执行（system/exec/shell_exec/passthru/popen/proc_open）、无代码执行（eval/assert/create_function/preg_replace /e）、无文件操作（include/require/fopen/file_get_contents/file_put_contents）、无反序列化（unserialize）、无 SQL 调用、无 setcookie/session 配置、无硬编码凭据或加密密钥。第 16-21 行的 generate_token() 使用 md5(rot13(phrase)) 生成 token，但该逻辑完全运行在浏览器端（客户端 JS），不构成服务端弱哈希/弱加密漏洞，且无服务端校验点可被利用，不满足 CVE 级发现条件。第 2 行 $page['body'] .= 依赖外部定义的 $page 变量，但该变量来源不在 code_pack 内，无法确认其是否被回显或参与危险操作，属未闭合线索，不报告。整体判断：本文件为某训练/靶场页面（如 DVWA 类）的前端片段，无可从外部触发的服务端漏洞链。

未覆盖 / 证据缺口：
- $page 变量的定义与最终输出位置不在 code_pack 内，无法确认是否存在 XSS 回显或其它下游汇点
- 无 composer.json/框架配置，无法评估依赖版本与已知 CVE
- 无 HTTP 端点、路由、参数清单，无法做污点链路测绘
- 无部署信息（PHP 版本、allow_url_include、register_globals 等），无法判断运行时可利用性
- surface_notes 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/hardcoded_secret/trust_boundary 候选均未在源码中找到对应证据，故不报告

## 3. Findings

### F-1: 客户端令牌生成使用 MD5 弱哈希（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`032.php:17-18`
- **来源**：`rule`

**描述**

在 032.php 第 17-18 行，页面脚本读取表单元素 phrase 的值（document.getElementById("phrase").value），随后执行 md5(rot13(phrase)) 并把结果写入隐藏/令牌字段 token（document.getElementById("token").value）。即令牌由客户端可完全控制的输入经 ROT13（无密钥的可逆替换）与 MD5（无盐、无迭代、已知碰撞的弱哈希）派生。攻击者只需知道或猜到 phrase 的取值即可离线复算出同一 token，无需任何密钥；ROT13 不提供任何机密性，MD5 也不提供抗碰撞/抗原像强度。校验环节（服务端对 token 的比对）在给定片段中未出现，因此“校验无效”的具体实现属证据不足，但令牌派生算法本身已构成弱哈希弱点。

**source / sink**

- source：repository `md5(`（032.php）
- sink：032.php:18 		document.getElementById("token").value = md5(rot13(phrase));

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `032.php:18` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（离线源码审计，不发送请求）：`032.php:18` 在客户端 JavaScript 中把用户输入的 `phrase`（`document.getElementById("phrase").value`）经 `rot13` 变换后交给 `md5()` 生成 `token` 字段值。该 token 由客户端可预测算法（ROT13 + MD5）派生，属于弱哈希/弱令牌生成（CWE-328 弱哈希，若该 token 被当作防伪/校验凭据使用则同时具备 CWE-327 弱加密语义）。攻击者无需密钥即可离线复算任意 `phrase` 对应的 token，从而绕过基于该 token 的校验或伪造请求。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 032.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-991eb6123bf3`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

令牌/校验值可被攻击者离线预测与伪造：任何能提交 phrase 的一方都能生成合法 token，从而绕过依赖该 token 的防篡改/防伪造校验，可能导致越权提交、请求伪造或业务逻辑绕过。由于是纯客户端计算，攻击者还可直接篡改 DOM 后提交任意 token 值。

**CVE / CWE 论证**

对应 CWE-328（Use of Weak Hash）：MD5 用于安全用途（令牌派生）且无盐、无密钥、无迭代；ROT13 为可逆替换，不构成密钥材料。外部可达性：该逻辑位于 032.php 返回给浏览器的脚本中，任何能访问该页面的未认证用户均可触发并观察/复算 token，利用链在客户端闭合，无需认证。注意：本条为配置/实现型弱点，不依赖 HTTP 污点链；服务端比对逻辑未在片段中出现，故不宣称已实现端到端绕过。

**修复建议**

1) 不要在客户端派生安全令牌：改由服务端使用 CSPRNG（如 Java SecureRandom / PHP random_bytes）生成至少 128 位随机令牌并绑定会话；2) 若必须做完整性校验，使用带密钥的 HMAC-SHA-256（服务端持有密钥）替代 md5(rot13(...))；3) 彻底移除 MD5 与 ROT13 在安全语义中的使用，口令场景改用 Argon2id/bcrypt/PBKDF2 并加盐；4) 服务端对 token 做常量时间比较并校验来源与会话绑定。

**验证说明**

静态证据：入口 ANY /032；source=repository/md5(；sink=032.php:18；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者访问 032.php → 页面脚本读取可控输入 phrase（第 17 行）→ 经 rot13 与 md5 计算（第 18 行）→ 写入 token 字段 → 攻击者可在本地复算或直接改写 token 后提交，令牌不再具备不可预测性。服务端校验代码未在证据中出现，端到端影响为推断。
POC 备注：本 POC 为静态证据工件，不执行、不联网、不搭建沙箱。目标地址如需引用统一写 `TARGET`。当前 code_pack 仅提供 032.php 第 17-19 行前端片段，服务端校验逻辑未覆盖，故未构造具体 HTTP 请求；如需请求级 POC，须补充服务端读取 `token` 的路由与字段名，不得伪造。

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
| `weak_crypto` | CWE-327 |  | 1 |
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
| safety_guard | 安全防护 | 3.13 | 是 |
| surface_mapper | 攻击面测绘 | 6.9 | 是 |
| deep_finder | LLM 深挖 | 3.5 | 是 |
| candidate_screener | 候选筛选 | 2.85 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.5 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.93 | 是 |
| coordinator | 管线协调 | 5.59 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
