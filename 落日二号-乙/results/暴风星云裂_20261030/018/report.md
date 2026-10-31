# 落日二号乙漏洞挖掘报告 — 20261030-224718-49e490

- 生成时间：2026-10-30T14:47:51.845118+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\018.zip`
- 输入模式：`zip`
- SHA256：`c4b42bf16d7ffb0d67ab50a7b701b39c7724a0451847bcfe91b4606313b9fcfd`
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

本次汇总仅含 1 条已去重 finding：LLM-67cf74d71eb3，类型 auth_bypass，严重度 high，位于单文件 PHP 应用 018.php（第 32 行附近），描述为使用 AES-128-ECB 与硬编码密钥保护会话令牌，可篡改伪造 admin 身份，已附带 POC（静态证据型，未做动态验证）。最高危即此条，也是唯一交付项。POC 齐全度为 1/1，但需注意该 POC 属源码推断+静态构造，不能宣称已动态复现。攻击面测绘指出 018.php:4 为超全局输入源、sink_hot_files 为空，注入类与配置类风险均未形成 finding，需人工通读全文复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3269 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 018.php（可见 1-56、65-110 行，57-64 行未送入）。核心问题：AES-128-ECB + 硬编码密钥 + 无完整性校验保护会话令牌，可伪造 admin 身份（认证绕过/权限提升）。第100行 $_SERVER['PHP_SELF'] 拼入表单 action 存在反射型 XSS 可能，但需依赖服务器对 PHP_SELF 的处理，证据不足以闭合，未单独立项。未发现命令执行、SQL 注入、文件操作等汇点。

未覆盖 / 证据缺口：
- 018.php 第57-64行未在 code_pack 中，未审计
- 无 HTTP 端点/部署信息，无法确认对外可达性与鉴权前置
- PHP_SELF 反射 XSS 未闭合，未报告

## 3. Findings

### F-1: 018.php 使用 AES-128-ECB 且硬编码密钥保护会话令牌，可被篡改伪造 admin 身份

- **类型**：`auth_bypass` / CWE-287
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`018.php:2-32`
- **来源**：`llm_finding`

**描述**

脚本用 openssl_decrypt($ciphertext, 'aes-128-ecb', $key, ...) 解密客户端提交的 token，密钥硬编码为 "ik ben een aardbei"（第10行），算法为 ECB 模式（第3行）。ECB 对相同明文块产生相同密文块且无完整性校验（无 HMAC/签名），攻击者拿到任意合法 token 后可在块粒度上重排/拼接/替换密文块，构造出 user=sweep、level=admin、ex 为未来时间的伪造令牌，从而通过第32行的管理员判定，实现认证绕过/权限提升。

**source / sink**

- source：body `token`（018.php:21）
- sink：018.php:32 018.php:32 基于解密后 JSON 字段的授权判定 $user->user=="sweep" && $user->level=="admin"

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `018.php:21` | 从 POST 读取攻击者可控 token | 十六进制字符串 |  |
| 2 | `018.php:22` | 仅校验长度是否为 32 的倍数，无签名/完整性校验 | 长度校验通过 |  |
| 3 | `018.php:25` | hex2bin 后交给 decrypt，使用硬编码密钥与 AES-128-ECB 解密 | 明文 JSON（ECB 块可重排） |  |
| 4 | `018.php:27` | json_decode 得到对象 | 对象 $user |  |
| 5 | `018.php:32` | 依据 user/level/ex 判定管理员，攻击者伪造字段即通过 | 授权判定为真 | ECB 无完整性保护且密钥硬编码，可离线构造任意明文对应密文 |

**POC**

针对 /018.php（POST）的认证绕过 POC。注入点：POST 参数 token（依据源码 018.php:32 对 body 参数 token 的取值与校验逻辑）；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/018.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 认证绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/018.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'token=admin'
```
预期：以未授权/伪造身份访问受保护资源返回 2xx。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`admin`
- POC 目录：`poc/LLM-67cf74d71eb3`
- 执行状态：未执行（`executed=False`）

**影响**

攻击者无需凭据即可伪造管理员会话，绕过认证获得 admin 权限。

**CVE / CWE 论证**

CWE-327 使用 ECB 弱加密 + CWE-798 硬编码密钥 + CWE-345 缺乏完整性校验，导致 CWE-287 认证绕过；外部 POST 直接可达，链闭合。

**修复建议**

改用 AES-GCM 等带认证的加密并加 HMAC 签名；密钥从安全配置读取，禁止硬编码；校验令牌完整性后再解析。

**验证说明**

需动态确认伪造 token 能被接受并返回 admin 成功提示；确认 ex 时间戳格式与 JSON 字段名完全匹配。
模型 POC 要点：利用 ECB 块重排/已知密钥离线加密，构造 user=sweep、level=admin、ex 为未来时间的 JSON，AES-128-ECB 加密后 hex 编码作为 token 提交。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /018.php）：符合 CWE-287。漏洞位于可交付代码 018.php:32，外部输入来自 body 参数 `token`，source→sink 链已静态闭合，且未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱；目标地址统一使用 TARGET 占位符，仅限授权测试。保留输入中确定性 POC 的请求结构（POST /018.php，body token=admin），仅补充说明与预期结果，未改动文件/行号与注入点。

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
| safety_guard | 安全防护 | 3.25 | 是 |
| surface_mapper | 攻击面测绘 | 8.95 | 是 |
| deep_finder | LLM 深挖 | 8.11 | 是 |
| candidate_screener | 候选筛选 | 3.12 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 3.76 | 是 |
| coordinator | 管线协调 | 6.58 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
