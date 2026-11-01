# 落日二号乙漏洞挖掘报告 — 20261031-214817-2a1c5d

- 生成时间：2026-10-31T13:49:03.979033+00:00
- 输入：`$WORKSPACE\暴风星云裂\042.zip`
- 输入模式：`zip`
- SHA256：`56c6109a46f6b0f847124698111455904f6d936639464da066a8713062e29119`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.5.0-ver5
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总仅含 1 条已去重 finding：042.php 第 2 行附近读取的 query 参数 id 被拼接进 SQL 语句，构成 SQL 注入（CWE-89），严重度 critical，已附带 POC（HTTP 型，可对 TARGET 复现，仅限授权测试）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 条 finding 有 POC；但该 POC 属静态推导的 HTTP 请求文本，未做动态验证。其余攻击面（命令执行、路径穿越、SSRF、XSS、弱哈希/弱随机/Cookie 标志、信任边界）在 surface_notes 中被列为优先审计点，但本次 findings 未覆盖，需人工复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2271 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计唯一文件 042.php（59 行）。发现 1 条闭合的 SQL 注入链：POST id 参数经 mysqli_real_escape_string 后仍以数值上下文拼接进 SQL，MYSQL 与 SQLITE 两个分支均受影响。未发现命令执行、文件操作、反序列化、SSRF 等其它汇点。weak_hash/weak_random/insecure_cookie 等配置类线索在代码中无对应实现，不成立。未覆盖范围：无端点清单、无部署配置、无认证文件，无法确认实际 URL 映射与访问控制。

未覆盖 / 证据缺口：
- 无端点清单，无法确认实际可访问路径
- 无认证/会话文件，无法判断访问控制
- 无数据库配置，无法确认 SQLI_DB 取值
- 无依赖清单，无法评估第三方库 CVE

## 3. Findings

### F-1: 042.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`042.php:10-12`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（042.php:5 读取该参数），该值未经任何过滤、类型转换或参数化，被直接拼接进 SQL 语句：042.php:11 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;"`，随后在 042.php:12 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 处于 WHERE 条件的数值位置且无引号包裹，攻击者可注入 `1 OR 1=1`、`1 UNION SELECT ...` 等片段改变查询语义；代码中不存在 mysqli_real_escape_string、intval、预处理语句或白名单校验，因此校验完全缺失。错误信息还会经 `mysqli_error(...)` 回显（042.php:12 的 die 分支），进一步泄露数据库结构，便于构造 UNION 注入。

**source / sink**

- source：query `id`（042.php:5）
- sink：042.php:12 $result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `042.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `042.php:12` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 042.php 的 SQL 注入 POC（POST 方法）。注入点为 POST 参数 id，源码在 042.php:12 处将该参数拼入 SQL 语句，未做有效净化。注意：本条草稿的 endpoint 写作 /042，与 file_path 042.php 不一致，需以源码实际路由为准。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/042'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/042' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-65bf75938433`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可读取 users 表之外的数据（如通过 UNION 提取数据库名、表名、其他表字段），造成敏感数据泄露；结合堆叠/写文件能力可能进一步导致数据篡改或服务器文件写入（取决于数据库权限）。错误回显降低了利用门槛。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问 042.php 触发；利用链闭合：source（042.php:5 的 `id`）→ 字符串拼接（042.php:11）→ 执行汇点 `mysqli_query`（042.php:12），中间无净化函数，链路完整。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用参数化查询：`$stmt = $GLOBALS["___mysqli_ston"]->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?"); $stmt->bind_param("i", $id); $stmt->execute();`；若必须拼接，先对 `$id` 做 `intval()` 强制数值化并校验范围。关闭向用户回显的 `mysqli_error` 详细信息，改为记录到服务端日志。数据库账号遵循最小权限，禁止 FILE 权限。

**验证说明**

静态证据：入口 POST /042；source=query/id；sink=042.php:12；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `042.php?id=1 UNION SELECT user,password FROM users`（示例，仅限授权测试，目标写 TARGET）→ 042.php:5 读取 `id` → 042.php:11 直接拼入 `$query` → 042.php:12 `mysqli_query` 执行被篡改的 SQL → 结果集返回并在页面渲染，实现数据泄露；若语法错误则 `mysqli_error` 回显辅助盲注/报错注入。
PocWriter 建议（未采纳，缺少端点 /042）：符合 CWE-89（SQL 注入）。漏洞位于 042.php:12，外部输入来自 POST body 参数 id，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。执行前将 TARGET 替换为授权测试环境地址；禁止在生产环境运行。草稿中 endpoint 为 /042 而 file_path 为 042.php，二者不一致，需以源码实际路由为准后再执行。

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
| `sql_injection` | CWE-89 | 是 | 1 |
| `blind_sql_injection` | CWE-89 |  | 0 |
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
| safety_guard | 安全防护 | 4.95 | 是 |
| surface_mapper | 攻击面测绘 | 9.1 | 是 |
| deep_finder | LLM 深挖 | 7.38 | 是 |
| candidate_screener | 候选筛选 | 4.38 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.02 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.3 | 是 |
| coordinator | 管线协调 | 6.13 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
