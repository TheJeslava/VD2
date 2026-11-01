# 落日二号乙漏洞挖掘报告 — 20261030-224558-657ffe

- 生成时间：2026-10-30T14:46:32.913096+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\008.zip`
- 输入模式：`zip`
- SHA256：`dfae4e0605b1c5ffe8c4a8291c00c73ea277b830eed60f0489dfec01c43f36a6`
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

本次汇总仅含 1 条已去重 finding：LLM-be8d58eeb7fa，类型 idor（BAC/IDOR），严重度 high，位于 008.php 第 47 行附近，判定依据为可篡改的 user_id Cookie 被用于查询任意用户资料，已附带 POC（HTTP 型，可动态复现，仅限授权测试）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 已具备。需强调：本次仅 1 个 PHP 文件进入 code_pack，无路由/端点清单、无服务器配置、无依赖清单，008.php 第 6 行 sink 与第 12 行 source 的具体函数与数据流未在输入中给出代码片段，因此注入类（command/sql/path/ssrf）与配置类（weak_hash/weak_random/weak_crypto/insecure_cookie/trust_boundary）均属未覆盖，不能据此断言不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3377 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅收到单文件 008.php 的前 65 行（共 96 行，第 66-96 行未送入）。已审计第 1-65 行：第 7 行 dvwaCurrentUser() 拼接进 SQL，但该函数为 DVWA 内部受控值，未作为外部污点报告；第 15-19 行 GET user_id 经纯数字校验与 intval，SQL 注入不可行；核心问题在第 30-33 行以客户端 Cookie user_id 作为身份依据，形成闭合的 IDOR/越权链（已报告）。第 58-65 行 bac_log 建表逻辑为固定 SQL，无外部输入。未闭合线索：第 66-96 行未提供，可能含日志写入或其它逻辑；weak_hash/weak_random/insecure_cookie 等配置类候选在已见代码中未出现 md5/sha1/rand/setcookie，无法确认。

未覆盖 / 证据缺口：
- 008.php 第 66-96 行未送入，未审计
- 无 Web 服务器配置，无法确认暴露面与前置认证
- 无端点清单，路由为推断
- weak_hash/weak_random/insecure_cookie 在已见代码中无证据

## 3. Findings

### F-1: DVWA 008.php 通过可篡改 user_id Cookie 实现越权访问任意用户资料（BAC/IDOR）

- **类型**：`idor` / CWE-639
- **严重度**：`high`
- **置信度**：`0.88`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`008.php:30-47`
- **来源**：`llm_finding`

**描述**

008.php 第 15-19 行从 $_GET['user_id'] 读取目标用户 ID，仅用 preg_match('/^\d+$/') 校验为纯数字后 intval 转换；第 30-33 行从客户端 Cookie $_COOKIE['user_id'] 读取“当前用户身份”，仅比较 $id == $cookie_id 即授予访问权限。Cookie 完全由攻击者控制，攻击者只需将 Cookie user_id 设置为任意目标用户 ID，同时 GET 参数 user_id 设为同一值，即可绕过归属校验，读取任意用户的 first_name/last_name/avatar（第 35-47 行）。服务端未使用会话中的真实身份（第 7-11 行查出的 $current_user_id/$role 在授权判断中完全未被使用），属于典型的信任客户端 Cookie 的访问控制缺陷。

**source / sink**

- source：cookie `user_id`（008.php:15）
- sink：008.php:47 mysqli_query 查询 users 表并输出 first_name/last_name/avatar（008.php:35-47）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:15` | 读取 GET 参数 action 与 user_id，进入越权分支 | 外部可控字符串 |  |
| 2 | `008.php:16` | preg_match 仅校验 user_id 为纯数字，不校验归属 | 数字字符串，通过格式校验 |  |
| 3 | `008.php:19` | intval 转换为整数 $id | 整数目标用户 ID |  |
| 4 | `008.php:30` | 从客户端 Cookie 读取 user_id 作为“当前身份” | 攻击者可控整数 $cookie_id |  |
| 5 | `008.php:33` | $id == $cookie_id 比较，攻击者令两者相等即通过 | 条件恒真（攻击者控制） | 归属校验基于客户端 Cookie，而非服务端会话身份；第 7-11 行查出的真实 $current_user_id 未被使用 |
| 6 | `008.php:35` | 以 $id 查询目标用户资料并渲染输出 | 任意用户资料被读取 |  |

**POC**

针对 /008.php（GET）的 越权 / IDOR POC。注入点：Cookie: user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 越权 / IDOR 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/008.php' \
  -H 'Cookie: user_id=2'
```
预期：使用其他对象 ID 返回他人数据或执行他人操作。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`2`
- POC 目录：`poc/LLM-be8d58eeb7fa`
- 执行状态：未执行（`executed=False`）

**影响**

任意已登录用户可越权读取其他用户（含管理员）的姓名、头像等资料，破坏访问控制边界，可结合枚举遍历全部用户。

**CVE / CWE 论证**

CWE-639 授权绕过（IDOR）。外部 HTTP 可达，无需高权限，仅需可控 Cookie；source→sink 链在 CODE PACK 内完整闭合（008.php:15→30→33→35→47）。

**修复建议**

授权判断必须使用服务端会话中的真实用户身份（如第 7-11 行查出的 $current_user_id），禁止信任客户端 Cookie 中的 user_id；对目标资源做归属校验。

**验证说明**

需确认 DVWA 会话中是否存在独立可信身份来源；确认 008.php 是否对外暴露及是否有前置认证。
模型 POC 要点：将 Cookie user_id 设为受害者 ID，GET 参数 user_id 设为同一值，即可读取受害者资料
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /008.php）：针对 008.php（GET 路由）的越权访问 / IDOR 文本 POC。注入通道为 Cookie `user_id`（源码 008.php:47 处读取该 Cookie 并用于对象归属判断），通过将 Cookie 值改为其他用户的对象标识（示例值 2）访问他人资源。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /008.php）：符合 CWE-639（Authorization Bypass Through User-Controlled Key）。漏洞位于可交付代码 008.php:47，外部输入来自 Cookie `user_id`，source→sink 链在给定代码范围内静态闭合，未发现有效归属校验或净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。所有请求中的主机统一为 TARGET:8080，实际测试时替换为授权目标。禁止对生产环境批量遍历 ID；建议仅在授权测试账号范围内验证 1~2 个相邻标识。若目标使用 HTTPS 或不同端口，请相应调整但不改变 Cookie 注入通道。

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
| `idor` | CWE-639 | 是 | 1 |
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
| safety_guard | 安全防护 | 3.18 | 是 |
| surface_mapper | 攻击面测绘 | 8.08 | 是 |
| deep_finder | LLM 深挖 | 8.53 | 是 |
| candidate_screener | 候选筛选 | 2.89 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 5.91 | 是 |
| coordinator | 管线协调 | 6.08 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
