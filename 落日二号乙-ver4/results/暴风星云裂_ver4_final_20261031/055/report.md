# 落日二号乙漏洞挖掘报告 — 20261031-173421-65b246

- 生成时间：2026-10-31T09:34:55.800733+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\055.zip`
- 输入模式：`zip`
- SHA256：`3e6e2cddd55f2250b6f1a0ec122303bfa0c923af602a09aecf8d75ca2f525ece`
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

本次汇总仅含 1 条已去重 finding：055.php 留言板 INSERT 语句 SQL 注入（CWE-89，critical，规则命中，带 POC），是当前最高危且唯一交付项。该文件为 24 行单文件 PHP 脚本，source 热点在 055.php:3、sink 热点在 055.php:1，属短链路污点传播，与 SQL 注入结论方向一致。POC 齐全度为 1/1，但该 POC 为静态源码推导的文本工件，未做动态验证。攻击面测绘提出的路径穿越/文件包含、弱哈希、弱随机、硬编码凭据、Cookie 标志、信任边界等风险点均未被 findings 覆盖，已转入人工复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1482 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 055.php（1-24 行，DVWA 风格 guestbook 提交页）。入口为 POST 参数 btnSign/mtxMessage/txtName（第 3、5、6 行），sink 为第 18-19 行拼接 SQL 后 mysqli_query。逐跳分析：$message 经 trim→strip_tags→addslashes→mysqli_real_escape_string→htmlspecialchars（第 5、9、10、11 行），$name 经 trim→preg_replace 过滤 script→mysqli_real_escape_string（第 6、14、15 行），两者在进入第 18 行字符串拼接前均已通过 mysqli_real_escape_string 转义引号与反斜杠，无法闭合引号逃逸，故不构成可申报的 SQL 注入；第 19 行 mysqli_error 回显仅在查询失败时输出数据库错误信息，属低价值信息泄露，未达 CVE 门槛。第 14 行 preg_replace 的 script 黑名单可被绕过（如嵌套/大小写/非 script 标签），但该值随后仍经 mysqli_real_escape_string 处理并仅写入数据库，本文件内不存在读取该字段并输出的汇点（无 SELECT 与回显逻辑），二次注入的存储读点与危险汇点均不在 code_pack 内，链路不闭合，按规则不报告。未发现命令执行、文件包含、反序列化、SSRF、弱哈希/弱随机/硬编码凭据等证据（文件内无 md5/sha1/rand/setcookie/include/exec 调用）。未覆盖范围：无 Web 服务器配置、php.ini、数据库连接与 guestbook 展示页（读取 comment/name 的页面），因此存储型 XSS 与二次 SQL 注入无法评估；这些缺口需在包含展示页的更大 code_pack 中复核。

未覆盖 / 证据缺口：
- 缺少 guestbook 展示页（读取 comment/name 并输出的代码），无法判断存储型 XSS 或二次 SQL 注入
- 缺少 php.ini / Web 服务器配置，无法确认 magic_quotes、错误显示等运行条件
- 缺少数据库连接初始化代码（$GLOBALS['___mysqli_ston'] 的来源）
- 无端点清单，实际访问路径与请求方法未确认

## 3. Findings

### F-1: 055.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`055.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 055.php 提交留言表单，外部输入在 055.php:5 被读入变量 $message（候选标注为 query `mtxMessage`，即留言内容字段）。该值未经任何转义或参数化，在 055.php:18 被直接拼接进 SQL 字符串：$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";，随后在 055.php:19 交由 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行。由于 $message 位于单引号字符串字面量内部，攻击者只需闭合单引号即可注入任意 SQL 片段（例如在 comment 值中构造 ' , (SELECT ...))-- - 之类的载荷），并可用注释符截断后续语句。代码中未见 mysqli_real_escape_string、预处理语句或类型白名单等任何净化措施，因此校验完全缺失。此外 055.php:19 的 or die(...) 分支会把 mysqli_error() 的原始错误信息回显到页面，为报错型注入提供了直接反馈通道。

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

数据库注入可导致 guestbook 库表数据被任意读取、篡改或删除（数据泄露与完整性破坏）；结合报错回显可逐步枚举库名、表名与字段内容。若数据库账号权限过高，还可通过堆叠/文件写入等手段进一步扩大影响，最严重情形可导致服务器上的任意文件写入乃至远程代码执行。该端点通常无需认证即可访问，外部攻击者可直接利用。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素的不当中和）。外部可达性：注入点位于 055.php 的公开留言提交处理逻辑，攻击者通过 HTTP 参数即可控制 $message；无需认证；利用链闭合：055.php:5 读取外部输入 → 055.php:18 字符串拼接构造 $query → 055.php:19 mysqli_query 执行，且 055.php:19 的 die(mysqli_error(...)) 回显错误信息，形成完整的注入与反馈闭环。

**修复建议**

1) 改用预处理语句与参数绑定：$stmt = $mysqli->prepare("INSERT INTO guestbook (comment, name) VALUES (?, ?)"); $stmt->bind_param('ss', $message, $name); $stmt->execute();，从根本上消除拼接。2) 若必须使用 mysqli_query，至少对 $message、$name 调用 mysqli_real_escape_string 并配合正确的字符集设置。3) 对输入做长度与字符白名单校验。4) 关闭错误回显，将 mysqli_error 写入服务端日志而非输出到响应体。5) 数据库账号遵循最小权限，仅授予 INSERT 权限，禁用 FILE 权限。

**验证说明**

静态证据：入口 POST /055；source=query/mtxMessage；sink=055.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在留言提交请求中构造含单引号的 comment 内容 → 055.php:5 将其读入 $message → 055.php:18 直接拼入 INSERT 语句的 VALUES ('$message', '$name') 单引号字面量中，闭合引号后注入任意 SQL → 055.php:19 mysqli_query 执行被污染的 $query，若失败则通过 die(mysqli_error(...)) 回显数据库错误，为攻击者提供注入结果反馈。
PocWriter 建议（未采纳，缺少端点 /055）：针对 055.php:19 的 SQL 注入 POC。源码中 POST 参数 mtxMessage 被直接拼入 SQL 查询（source→sink 静态闭合，未见有效净化），通过布尔恒真条件改变查询结果。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /055）：符合 CWE-89（SQL 注入）。漏洞位于 055.php:19，外部输入来自 POST 参数 mtxMessage，source→sink 链静态闭合且未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。所有请求中的主机统一为 TARGET:8080，实际测试时按部署替换。禁止使用 DROP 等破坏性语句；布尔对比即可证明注入存在。若源码中触发按钮字段名与 Submit 不一致，需以源码为准补充（当前依据输入给出的 Submit=Submit）。

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
| safety_guard | 安全防护 | 3.26 | 是 |
| surface_mapper | 攻击面测绘 | 7.65 | 是 |
| deep_finder | LLM 深挖 | 3.77 | 是 |
| candidate_screener | 候选筛选 | 2.76 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.09 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.05 | 是 |
| coordinator | 管线协调 | 5.98 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
