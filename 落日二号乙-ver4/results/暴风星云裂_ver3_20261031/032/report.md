# 落日二号乙漏洞挖掘报告 — 20261031-010233-b1d82c

- 生成时间：2026-10-30T17:03:11.469047+00:00
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

本次汇总仅基于单文件 PHP 项目 032.php（24 行）的静态审计证据，共交付 1 条 finding：SEM-991eb6123bf3，类型 weak_crypto（实际语义为 MD5 弱哈希，CWE-328，非 CWE-327），严重度 medium，位于 032.php 第 18 行，已附带 POC。最高危项即该条 medium 弱哈希问题，属于静态证据型 POC，不能宣称可动态复现。POC 齐全度为 1/1（with_poc=1），但全部为静态/配置类证据，无任何 HTTP 请求级 POC。本次未产出注入、XSS、路径穿越、命令执行等污点链结论，原因是输入未提供 source/sink 热点标注与端点清单，属于证据不足而非已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 4350 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单个 PHP 文件 032.php（24 行），已逐行审计。该文件实际内容为：第 1 行 `<?php`，第 2 行开始用 heredoc 向 `$page['body']` 追加一段纯前端 HTML/JS（内嵌 blueimp JavaScript-MD5 库、rot13 函数、generate_token 函数），第 23 行结束 heredoc，第 24 行 `?>`。全文件不存在任何服务端外部输入读取（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER/$_FILES），不存在任何服务端 sink（无 exec/system/passthru/shell_exec/proc_open、无 eval/assert/create_function、无 include/require、无 fopen/file_get_contents、无 SQL 调用、无 curl、无 setcookie/session 配置、无 md5()/sha1() 服务端调用、无硬编码凭据）。第 18 行的 `md5(rot13(phrase))` 是浏览器端 JavaScript 计算，用于把页面输入框 `phrase` 的值转成 `token` 输入框的值，属于客户端逻辑，不构成服务端 weak_hash/weak_crypto 漏洞链，也无法从外部触发服务端危险操作。surface_notes 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 复核项在代码中均无对应实现，属于结构性推断而非已确认候选。因此没有满足 source→sink 闭合条件的 CVE 级发现，返回空 findings。未闭合线索：该脚本被哪个页面/框架包含、`$page` 变量由谁初始化、`phrase`/`token` 表单提交到哪个后端处理，均不在 code_pack 内，按契约视为不存在，无法进一步追踪。

未覆盖 / 证据缺口：
- 无端点清单与路由配置，无法确认 032.php 的实际访问 URL 与参数
- 无 Web 服务器/php.ini 配置，无法判断 register_globals、allow_url_include 等
- 无 composer.json/依赖清单
- 无认证/会话实现证据
- `$page` 变量来源与 `phrase`/`token` 表单的后端处理逻辑不在 code_pack 内

## 3. Findings

### F-1: 客户端使用 MD5 生成令牌（CWE-328 弱哈希，非 CWE-327 弱加密）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`032.php:17-18`
- **来源**：`rule`

**描述**

证据来自 032.php 第 17-18 行：第 17 行 `var phrase = document.getElementById("phrase").value;` 从页面输入框读取用户口令/短语，第 18 行 `document.getElementById("token").value = md5(rot13(phrase));` 先对短语做 ROT13（可逆替换，无任何密钥），再调用客户端 JavaScript 的 `md5()` 生成令牌并写入隐藏/可见字段 `token`。攻击者输入点即页面元素 `phrase` 的值；数据流为 phrase → rot13(phrase) → md5(...) → token 字段。校验无效的原因在于：ROT13 只是字母置换，不提供机密性；MD5 是快速、无盐、无迭代的哈希，且整条计算在浏览器端完成，算法与过程对攻击者完全可见，因此该“令牌”不具备抗猜测/抗伪造能力。需要说明的证据缺口：输入片段仅包含 17-19 行，未给出 `md5()` 的实现来源（内联还是外部脚本）、`token` 字段最终提交到哪个服务端端点、服务端是否再次校验或加盐，因此“令牌可被离线伪造并直接通过服务端校验”这一环属于基于源码的推断，未获外部证据佐证。

**source / sink**

- source：repository `md5(`（032.php）
- sink：032.php:18 		document.getElementById("token").value = md5(rot13(phrase));

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `032.php:18` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：在 `032.php:18` 记录问题，无需发送请求。

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

若该 token 被用作会话标识、表单防伪令牌或口令派生凭据，攻击者可离线枚举常见口令：对候选口令执行同样的 rot13+md5 计算并与截获的 token 比对，即可还原原始短语（口令恢复/离线爆破）；由于无盐且确定性，相同短语在不同用户/会话产生相同 token，可被用于重放或跨用户令牌碰撞。不构成直接的 RCE 或文件读写，影响面限于凭据保密性与令牌不可伪造性。

**CVE / CWE 论证**

对应 CWE-328（Use of Weak Hash）；输入候选标注的 CWE-327 属分类偏差，MD5 用于令牌/口令派生应归为弱哈希而非弱加密算法。外部可达性：该逻辑位于 032.php 渲染的页面脚本中，任何能访问该页面的用户均可触发；无需认证即可在客户端复现算法。利用链闭合度：客户端计算环节闭合（输入→rot13→md5→token），但“token 被服务端信任”这一末端环节在给定片段中缺失，故整体链为部分闭合，置信度按推断处理。

**修复建议**

1) 停止在客户端生成任何安全令牌：令牌应由服务端使用 CSPRNG（如 Java `SecureRandom`、PHP `random_bytes`）生成并仅存于服务端会话；2) 若必须对短语做派生，改用带盐、慢速的口令哈希（Argon2id、scrypt、PBKDF2-HMAC-SHA256 且迭代次数足够），并在服务端执行；3) 移除 ROT13 这类可逆混淆，它不提供任何安全属性；4) 对提交的 token 做服务端强校验（一次性、绑定会话、带过期时间），避免仅依赖客户端字段；5) 全站启用 HTTPS 防止 token 在传输中被截获。

**验证说明**

静态证据：入口 ANY /032；source=repository/md5(；sink=032.php:18；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者打开 032.php 页面，在 `phrase` 输入框填入候选口令；页面脚本第 17 行读取该值，第 18 行执行 `md5(rot13(phrase))` 并把结果写入 `token` 字段。由于算法公开、无盐、确定性且完全在客户端执行，攻击者可离线对字典中的每个候选口令重复同一计算，与截获的 token 逐一比对，命中即还原原始短语；相同短语还会产生相同 token，可被重放。末端“服务端接受该 token”的环节未在给定代码片段中出现，属推断部分。

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
| safety_guard | 安全防护 | 2.62 | 是 |
| surface_mapper | 攻击面测绘 | 8.03 | 是 |
| deep_finder | LLM 深挖 | 3.53 | 是 |
| candidate_screener | 候选筛选 | 3.18 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.98 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.28 | 否 |
| coordinator | 管线协调 | 6.22 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
