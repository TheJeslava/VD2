# 落日二号乙漏洞挖掘报告 — 20261031-001941-daeb12

- 生成时间：2026-10-30T16:20:18.316166+00:00
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

本次汇总仅包含 1 条已去重 finding：LLM-67cf74d71eb3（auth_bypass，high），位于单文件 PHP 脚本 018.php 第 32 行附近，问题为使用 AES-128-ECB 加密会话令牌并硬编码密钥，可伪造 admin 令牌绕过认证；该条已附带 POC（静态/构造型 POC，未做动态验证）。最高危即此条 auth_bypass。POC 齐全度为 1/1，但均为文本工件，未执行、未搭建沙箱、未做动态复现。其余攻击面（018.php:4 的 source 热点下游数据流、include/exec/eval 汇点、输出回显、弱哈希/弱加密/弱随机/不安全 Cookie/信任边界）在本次 findings 中均无对应条目，属未覆盖，需人工复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3269 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单文件 018.php（110 行，展示 1-56 与 65-110）。审计发现核心问题：会话令牌使用 AES-128-ECB 且密钥硬编码（第 2-10 行），令牌无完整性校验，第 32 行仅凭解密字段判定 admin 身份，构成认证绕过/令牌伪造，已给出闭合利用链与 POC。其余攻击面：第 88/92/96 行将 $errors/$messages/$success 拼入 HTML，但这些值来自固定字符串或异常消息（异常消息为固定文本），未见攻击者可控内容直接回显，未构成 XSS；第 100 行 $_SERVER['PHP_SELF'] 拼入 form action，存在反射型 XSS 的理论可能（PHP_SELF 可含路径信息），但利用依赖服务器对 PATH_INFO 的处理，证据不足，未单独立项。未发现命令执行、文件包含、SQL 拼接、反序列化等汇点。第 57-64 行因截断未展示，可能含另一令牌文本，但不影响结论。

未覆盖 / 证据缺口：
- 第 57-64 行未在 code_pack 中展示
- 缺少部署配置（php.ini、Web 服务器配置），无法确认 PHP_SELF 反射 XSS 的可利用性
- 无端点清单，无法确认实际访问路径与前置 WAF

## 3. Findings

### F-1: 018.php 使用 AES-128-ECB 加密会话令牌且硬编码密钥，可伪造 admin 令牌绕过认证

- **类型**：`auth_bypass` / CWE-287
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`018.php:2-32`
- **来源**：`llm_finding`

**描述**

018.php 第 2-8 行的 decrypt() 使用 openssl_decrypt 以 'aes-128-ecb' 模式解密，第 10 行硬编码密钥 $key = "ik ben een aardbei"。第 21 行从 $_POST['token'] 接收攻击者可控的十六进制令牌，第 25 行 hex2bin 后解密，第 27 行 json_decode，第 32 行仅凭解密出的 JSON 字段 user=="sweep"、ex>time()、level=="admin" 即判定为管理员登录成功。由于 ECB 模式为确定性分组加密、无完整性校验（无 MAC/签名），且密钥硬编码在源码中，攻击者可用已知明文分组（页面第 52 行泄露的 Sooty 令牌、第 69-74 行文档给出的 JSON 格式）进行分组重排/拼接，构造出 user=sweep、level=admin、ex 为未来时间的合法密文，从而以管理员身份登录。

**source / sink**

- source：body `token`（018.php:21）
- sink：018.php:32 018.php:32 认证判定 if ($user->user == "sweep" && $user->ex > time() && $user->level == "admin")

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `018.php:21` | 从 POST 参数 token 读取攻击者可控的十六进制字符串 | 原始十六进制字符串 |  |
| 2 | `018.php:22` | 仅校验长度是否为 32 的倍数，无内容/完整性校验 | 长度合法的十六进制串 | 只做长度检查，不校验 MAC/签名 |
| 3 | `018.php:25` | hex2bin 转为二进制后调用 decrypt()，使用硬编码密钥与 aes-128-ecb 解密 | 解密后的明文 JSON 字符串 | ECB 确定性加密 + 硬编码密钥，可离线构造密文 |
| 4 | `018.php:27` | json_decode 解析明文为对象 | JSON 对象 $user |  |
| 5 | `018.php:32` | 依据 user/ex/level 字段判定管理员登录成功 | 伪造的 admin 身份被接受 | 无签名校验，字段完全由攻击者控制 |

**POC**

针对 /018.php（POST）的认证绕过 POC。注入点为 POST 参数 token，源码 018.php:32 处将请求体中的 token 直接用于身份判定，未做有效校验/净化，提交 token=admin 即可伪造管理员身份。目标地址统一使用 TARGET 占位符，仅限授权测试。

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
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

攻击者无需任何凭据即可伪造管理员会话令牌，以 admin 身份登录，完全绕过认证。

**CVE / CWE 论证**

CWE-327（使用有风险的加密算法 ECB）+ CWE-798（硬编码密钥）+ CWE-345（缺乏完整性校验）导致认证绕过；外部可通过 POST 直接触发，无需认证，链路闭合。

**修复建议**

改用带认证的加密（如 AES-GCM 或 HMAC 签名），密钥从安全配置/环境变量加载，禁止 ECB 模式，并对令牌做完整性校验。

**验证说明**

需动态确认伪造密文能被正确解密并通过第 32 行判定；需确认 PHP openssl 对 PKCS1_PADDING 参数的实际行为（该常量用于 RSA，AES 下可能被忽略）。
模型 POC 要点：利用硬编码密钥 'ik ben een aardbei' 与 AES-128-ECB 无完整性校验，离线构造 {"user":"sweep","ex":<未来时间戳>,"level":"admin"} 的密文并十六进制编码后提交。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /018.php）：符合 CWE-287（Improper Authentication）。漏洞位于可交付代码 018.php:32，外部输入来自 POST body 的 token 参数，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权测试目标，并确认已获授权。原始确定性 POC 的请求结构（POST /018.php，body token=admin）予以保留，仅补充说明与预期结果。

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
| safety_guard | 安全防护 | 2.48 | 是 |
| surface_mapper | 攻击面测绘 | 10.36 | 是 |
| deep_finder | LLM 深挖 | 10.63 | 是 |
| candidate_screener | 候选筛选 | 2.5 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 4.02 | 是 |
| coordinator | 管线协调 | 6.8 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
