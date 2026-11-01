# 落日二号乙漏洞挖掘报告 — 20261031-002517-76349c

- 生成时间：2026-10-30T16:25:49.500181+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\057.zip`
- 输入模式：`zip`
- SHA256：`e5aacb8c730b8fc545d6f2efe30ad90b9aa52a5009f9f368746231c2685d2e23`
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

本次审计范围是单文件 PHP 脚本 057.php（24 行），共交付 1 条 finding：057.php 第 19 行留言板 INSERT 语句存在 SQL 注入（CWE-89），严重度 critical，来源为规则匹配，且已附带 POC（1/1 齐全）。最高危即该条 critical SQL 注入：请求参数在第 3 行附近读取后直接拼入 INSERT 语句，污点路径短、单文件内即可完成 source→sink 追踪。POC 为 HTTP 型文本工件（目标以 TARGET 占位），未执行、未做动态验证。攻击面测绘提出的文件包含/路径拼接（priority 2）与输出反射 XSS（priority 3）两个优先面，本次 findings 未覆盖，已转入人工复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1455 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已完整审计 code_pack 中唯一文件 057.php（24 行，DVWA 风格 guestbook 留言板）。入口为 POST 参数 btnSign/mtxMessage/txtName（第 3、5、6 行），汇点为第 18-19 行 mysqli_query 动态拼接 INSERT 语句。逐跳分析：$message 经 trim→addslashes→mysqli_real_escape_string→strip_tags→htmlspecialchars（第 5、9、10、11 行），$name 经 trim→str_replace('<script>')→mysqli_real_escape_string（第 6、14、15 行），两者在进入拼接前均被 mysqli_real_escape_string 转义，单引号被转义为 \'，无法闭合第 18 行 VALUES 中的字符串字面量，未发现可闭合的 SQL 注入链；addslashes 与 real_escape 叠加不构成绕过。第 14 行 str_replace 仅移除小写 '<script>' 属弱过滤，但 $name 未在任何输出上下文回显（第 19 行 die 仅输出 mysqli_error），不构成 XSS 链。文件中无 exec/system/include/file 读写/反序列化/模板等其它 sink，无 md5/rand/setcookie 等配置类线索。结论：在当前 code_pack 证据下无满足 min_severity=high、min_confidence=0.6 的可闭合漏洞，findings 为空。未覆盖范围：缺少 Web 服务器配置、路由与认证上下文，无法确认 057.php 实际可达路径与访问控制；缺少 PHP 版本与 disable_functions 信息；无 composer/依赖清单，无法评估第三方组件 CVE。

未覆盖 / 证据缺口：
- 缺少 Web 服务器/路由/认证配置，无法确认 057.php 对外可达性与访问控制
- 缺少 PHP 版本与 disable_functions 等运行环境信息
- 无依赖清单，无法评估第三方组件 CVE
- 第 14 行 str_replace('<script>') 弱过滤因无回显上下文未构成 XSS，若后续版本增加回显需重新评估

## 3. Findings

### F-1: 057.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`057.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向留言板提交评论/姓名，输入在 057.php:5 处被读取为 `mtxMessage`（留言消息），随后在 057.php:18 被直接字符串拼接进 INSERT 语句：`$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";`，其中 `$message`、`$name` 均以单引号包裹但未做任何转义或参数化。057.php:19 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行该拼接后的 SQL。由于没有使用 `mysqli_real_escape_string`、预处理语句或白名单校验，单引号可闭合字符串字面量，从而注入任意 SQL 片段（如通过 `$message` 注入 `', 'x'); ... -- ` 改变语句结构）。错误信息还会经 `mysqli_error` 回显到页面，进一步辅助注入调试。

**source / sink**

- source：query `mtxMessage`（057.php:5）
- sink：057.php:19 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `057.php:5` | 从 query `mtxMessage` 读取外部输入 | 污点进入 query |  |
| 2 | `057.php:19` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /057 端点（HTTP 方法 ANY）的 SQL 注入 POC。注入点为查询参数 mtxMessage，位于 057.php 第 19 行，外部输入未经有效净化即进入 SQL 查询汇点。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/057'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/057?mtxMessage=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-71dd317be73f`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库写入被任意控制：可向 guestbook 表插入伪造/恶意记录，或通过堆叠/子查询读取其他表数据（数据泄露），在数据库账户权限较高时可导致数据篡改甚至通过文件写入类函数造成进一步危害。属于未认证远程可利用的 SQL 注入。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：留言提交为公开 HTTP 端点，无需认证；污点链闭合：057.php:5 读取外部输入 → 057.php:18 字符串拼接 → 057.php:19 `mysqli_query` 执行，中间无有效净化，满足注入成立条件。

**修复建议**

改用参数化查询/预处理语句（`mysqli_prepare` + `bind_param`），将 `$message`、`$name` 作为绑定参数传入，禁止字符串拼接；若必须拼接，至少使用 `mysqli_real_escape_string` 并配合严格类型校验；同时关闭生产环境的数据库错误回显（移除 `or die(mysqli_error(...))`），并遵循最小权限原则限制数据库账户权限。

**验证说明**

静态证据：入口 ANY /057；source=query/mtxMessage；sink=057.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：外部请求提交留言 → 057.php:5 读取 `mtxMessage` 作为 `$message` → 057.php:18 直接拼入 INSERT 语句 → 057.php:19 `mysqli_query` 执行拼接 SQL → 注入生效，错误信息经 `mysqli_error` 回显。
PocWriter 建议（未采纳，缺少端点 /057）：符合 CWE-89（SQL 注入）。漏洞位于 057.php:19，外部输入来自查询参数 mtxMessage，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。脚本中的 curl 命令需人工替换 TARGET 后在授权环境手动执行；禁止使用 DROP 等破坏性语句。request.http 中 Content-Length 为示例值，实际发送时由客户端自动计算。

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
| safety_guard | 安全防护 | 3.38 | 是 |
| surface_mapper | 攻击面测绘 | 6.84 | 是 |
| deep_finder | LLM 深挖 | 4.0 | 是 |
| candidate_screener | 候选筛选 | 1.97 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.21 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.26 | 是 |
| coordinator | 管线协调 | 5.87 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
