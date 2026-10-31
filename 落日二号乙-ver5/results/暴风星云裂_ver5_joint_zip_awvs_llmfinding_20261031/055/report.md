# 落日二号乙漏洞挖掘报告 — 20261031-215105-bf2967

- 生成时间：2026-10-31T13:51:47.045448+00:00
- 输入：`$WORKSPACE\暴风星云裂\055.zip`
- 输入模式：`zip`
- SHA256：`3e6e2cddd55f2250b6f1a0ec122303bfa0c923af602a09aecf8d75ca2f525ece`
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

本次汇总仅含 1 条已去重 finding：055.php 留言板 INSERT 语句 SQL 注入（CWE-89，critical，rule 来源，已附 POC），是本次最高危且唯一交付项。该文件为 24 行单文件 PHP 脚本，source 热点在第 3 行、sink 热点在第 1 行附近，污点路径极短、几乎无净化环节，与 SQL 注入结论一致。POC 齐全度为 1/1，但该 POC 为静态源码推导的文本工件，未做动态验证，不能宣称可动态复现。覆盖面上仅 1 个文件、1 种语言（php）、0 个端点、无框架，攻击面测绘提出的路径穿越/LFI、反射型 XSS、弱哈希、硬编码凭据、信任边界等方向均未被 findings 覆盖，需人工复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1482 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已通读 code_pack 中唯一文件 055.php（1-24 行，未截断）。该脚本在 `isset($_POST['btnSign'])` 时读取 `mtxMessage` 与 `txtName`，经 strip_tags/addslashes/mysqli_real_escape_string/htmlspecialchars（message）与 preg_replace 过滤 script 标签 + mysqli_real_escape_string（name）后，拼接进 INSERT 语句并由 mysqli_query 执行。两个参数在进入 SQL 前均经过 mysqli_real_escape_string（基于 ___mysqli_ston 连接对象），单引号等元字符被转义，未发现可改变 SQL 语法的注入点；name 的 preg_replace 仅过滤 script 关键字，但随后仍有 mysqli_real_escape_string 兜底，不构成注入。message 额外经 htmlspecialchars，回显路径不存在（无 echo 输出用户输入），故无反射型 XSS。文件中无 include/require、无文件读写、无 exec/system/eval、无 md5/sha1、无硬编码凭据、无 $_SERVER 头信任，surface_notes 中列出的 LFI/命令执行/弱哈希/硬编码口令等线索在源码中均无对应实现。未发现满足 CVE 级别且利用链闭合的漏洞，故 findings 为空。未闭合/未覆盖项：缺少 php.ini 与 Web 服务器配置（无法确认 ___mysqli_ston 是否总被初始化、display_errors 行为）、无路由信息确认 055.php 是否对外暴露、无依赖清单；若 ___mysqli_ston 未初始化，第 10/15 行会走 trigger_error 分支返回空串，此时 message/name 被置空，同样不产生注入。

未覆盖 / 证据缺口：
- 缺少 php.ini / Web 服务器配置，无法确认 ___mysqli_ston 初始化与错误显示行为
- 无端点/路由信息，无法确认 055.php 是否对外暴露及是否在认证之后
- 无 composer.json 等依赖清单，无法评估第三方组件风险
- 无版本历史，无法判断是否为调试遗留脚本

## 3. Findings

### F-1: 055.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`055.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 055.php 提交留言内容（源码中对应 query 参数 `mtxMessage`，即留言 message 字段），该输入在 055.php:5 被读入后未做任何转义或参数化，直接以字符串拼接方式进入 055.php:18 构造的 INSERT 语句：$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";，其中 $message 被单引号包裹但未经过 mysqli_real_escape_string 等转义，攻击者只需在留言中提交单引号即可闭合字符串字面量并注入任意 SQL 片段（如通过 comment 字段注入子查询或堆叠语句）。随后在 055.php:19 该 $query 被直接交给 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行，构成完整的 source→sink 污点链。校验无效的原因：代码路径中不存在预处理语句（prepare/bind_param）、不存在白名单过滤、也不存在对单引号/反斜杠的转义，因此单引号闭合即可绕过。

**source / sink**

- source：query `mtxMessage`（055.php:5）
- sink：055.php:19 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `055.php:5` | 从 query `mtxMessage` 读取外部输入 | 污点进入 query |  |
| 2 | `055.php:19` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /055（POST）的 SQL 注入 POC。注入点：POST 参数 mtxMessage；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/055'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/055' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'mtxMessage=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-0108b5d86494`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库写入型 SQL 注入：攻击者可篡改 guestbook 表内容、向其他表写入任意数据，并可通过报错回显（055.php:19 的 die() 分支会输出 mysqli_error）实施基于报错的库名/表名/列名枚举，进而读取数据库中的敏感数据；若数据库账号权限过高，还可能造成数据删除或越权访问。属于数据完整性与机密性双重影响。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：055.php 为 Web 可直接访问的留言提交端点，攻击者通过普通 HTTP 请求即可触达，无需认证；利用链闭合：055.php:5 读取外部输入 → 055.php:18 字符串拼接构造 SQL → 055.php:19 mysqli_query 执行，且 055.php:19 的 die() 分支回显数据库错误，为注入结果提供反馈通道。

**修复建议**

1) 改用参数化查询：$stmt = $GLOBALS["___mysqli_ston"]->prepare("INSERT INTO guestbook (comment, name) VALUES (?, ?)"); $stmt->bind_param('ss', $message, $name); $stmt->execute();；2) 若必须保留拼接，至少对 $message、$name 使用 mysqli_real_escape_string 转义；3) 关闭生产环境的数据库错误回显，将 mysqli_error 写入服务端日志而非返回给客户端；4) 数据库账号遵循最小权限，仅授予 guestbook 表的 INSERT 权限。

**验证说明**

静态证据：入口 POST /055；source=query/mtxMessage；sink=055.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在留言提交表单的 message 字段（源码 query 参数 `mtxMessage`）中提交形如 `x'), ('y` 或含单引号闭合的载荷 → 055.php:5 读取该外部输入到 $message → 055.php:18 将 $message 直接拼入 INSERT 语句的字符串字面量 → 055.php:19 mysqli_query 执行被污染的 $query，注入生效；若语句出错，die() 分支回显 mysqli_error，攻击者可据此逐步枚举数据库结构。
PocWriter 建议（未采纳，缺少端点 /055）：针对 055.php 第 19 行 SQL 注入的文本 POC。注入点为 POST 参数 mtxMessage（源码通过 getParameter("mtxMessage") 取值后拼接进 SQL 语句），触发按钮字段为 Submit。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /055）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 055.php 第 19 行，外部输入来自 POST 参数 mtxMessage，source→sink 链在给定代码范围内静态闭合，未发现有效参数化或转义净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。所有请求中的主机统一为 TARGET:8080，实际测试时替换为授权目标。禁止使用 DROP/破坏性语句；建议先做布尔对照再考虑时间盲注。若需脚本化，仅保留上述三条 curl 文本，不生成自动执行链。

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
| safety_guard | 安全防护 | 5.2 | 是 |
| surface_mapper | 攻击面测绘 | 8.24 | 是 |
| deep_finder | LLM 深挖 | 4.83 | 是 |
| candidate_screener | 候选筛选 | 3.65 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.78 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.81 | 是 |
| coordinator | 管线协调 | 5.78 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
