# 落日二号乙漏洞挖掘报告 — 20261031-002516-eba959

- 生成时间：2026-10-30T16:25:53.532641+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\056.zip`
- 输入模式：`zip`
- SHA256：`ddeedf015a89af3c4e7d2a26f3eadc8b063046e52cecc3d299334e66c93a1d75`
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

本次汇总仅含 1 条已去重 finding：056.php 第 17 行附近的留言板 INSERT 语句 SQL 注入（CWE-89），严重度 critical，来源为规则命中，已附带 POC（HTTP 型，可动态复现）。这是本次唯一交付项，也是最高危项。POC 齐全度为 1/1，但该 POC 属 HTTP 型，需在授权环境自行验证，本管线未做动态验证。其余攻击面（命令执行、路径穿越/文件包含、反射型 XSS、弱哈希/弱加密/弱随机、Cookie 标志、信任边界、硬编码凭据）在 surface_notes 中被列为待核查点，但本次 findings 未覆盖，已转入 human_review，不能据此宣称不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1342 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 056.php（1-22 行，DVWA 风格 guestbook 提交片段）。入口为 POST 参数 btnSign/mtxMessage/txtName（第 3、5、6 行），sink 为第 16-17 行拼接 INSERT 语句后 mysqli_query。关键点：第 10、13 行对 $message 与 $name 均调用 mysqli_real_escape_string（连接对象为 $GLOBALS['___mysqli_ston']），在连接字符集为默认（非 GBK 等宽字节）时单引号被转义，字符串字面量无法闭合，未发现可闭合的 SQL 注入链；第 9 行 stripslashes 在转义之前执行，不构成绕过。第 17 行 die() 输出 mysqli_error，属错误信息泄露（低危，低于 min_severity=high，不单独立项）。未发现命令执行、文件包含、反序列化、SSRF、模板等其它 sink；文件中无 md5/sha1/rand/setcookie/硬编码密钥等配置型证据。未闭合线索：若部署时连接字符集为 GBK/big5 等宽字节字符集，mysqli_real_escape_string 可被 %df%27 类宽字节绕过，但 code_pack 未提供连接初始化与字符集设置代码，无法确认，故不报告。code_pack 之外文件视为不存在；无 endpoints、无配置与依赖信息，未覆盖部署层可利用性。

未覆盖 / 证据缺口：
- 未提供数据库连接与字符集设置代码，无法判定宽字节注入是否成立
- 无 php.ini/Web 服务器配置，无法判断错误显示与暴露面
- 无认证/会话代码，无法评估 guestbook 写入的权限边界
- endpoints 为空，实际 URL 与参数绑定未确认

## 3. Findings

### F-1: 056.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`056.php:15-17`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 056.php 提交留言内容（源码中对应变量 $message，候选描述里写作 query `mtxMessage`，即请求参数 mtxMessage），该值在 056.php:5 被读入后未做任何转义或参数化处理，于 056.php:16 被直接拼接进 SQL 字符串：$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";，随后在 056.php:17 交给 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行。由于 $message 被包裹在单引号内且未调用 mysqli_real_escape_string 或使用预处理语句，攻击者只需在参数中闭合单引号即可跳出字符串上下文，改写 INSERT 语句结构（例如追加子查询、改变 VALUES 表达式，或利用报错回显做布尔/报错注入）。校验无效的原因是该路径上不存在白名单、类型转换或转义函数，污点从读取点直达执行点。

**source / sink**

- source：query `mtxMessage`（056.php:5）
- sink：056.php:17 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `056.php:5` | 从 query `mtxMessage` 读取外部输入 | 污点进入 query |  |
| 2 | `056.php:17` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /056（ANY）的 SQL 注入 POC。注入点：ANY 参数 mtxMessage；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/056'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/056?mtxMessage=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-23ca13029614`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库写入逻辑可被攻击者任意改写：可向 guestbook 表注入任意内容（存储型二次风险）、通过报错信息（056.php:17 的 die() 会回显 mysqli_error）泄露数据库结构、库名、表名与版本；结合堆叠/子查询可读取其他表数据，造成数据泄露与数据完整性破坏。若数据库账户权限过高，还可进一步写入文件或篡改业务数据。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素的不当中和）。外部可达性：056.php 为可直接 HTTP 访问的脚本，注入点为请求参数 mtxMessage，无需认证即可提交；利用链闭合：056.php:5 读取外部输入 → 056.php:16 字符串拼接构造 $query → 056.php:17 mysqli_query 执行，中间无净化函数，且 die(mysqli_error(...)) 提供报错回显通道，满足未授权远程利用条件。

**修复建议**

1) 改用预处理语句：$stmt = $mysqli->prepare("INSERT INTO guestbook (comment, name) VALUES (?, ?)"); $stmt->bind_param('ss', $message, $name); $stmt->execute();；2) 若必须拼接，至少对 $message、$name 使用 mysqli_real_escape_string 并配合正确的字符集设置；3) 对输入做长度与字符白名单校验；4) 关闭错误回显，将 mysqli_error 写入服务端日志而非返回给客户端；5) 数据库账户遵循最小权限，仅授予 guestbook 表的 INSERT 权限。

**验证说明**

静态证据：入口 ANY /056；source=query/mtxMessage；sink=056.php:17；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 056.php 提交 POST/GET 参数 mtxMessage，值形如 ' , (SELECT ...))-- - ；056.php:5 将该值赋给 $message；056.php:16 直接把 $message 拼进 INSERT INTO guestbook (comment, name) VALUES ('$message', '$name') 的单引号内；056.php:17 调用 mysqli_query 执行被篡改的语句，若语法/逻辑出错则 die() 回显 mysqli_error，攻击者据此逐步提取数据库信息。
PocWriter 建议（未采纳，缺少端点 /056）：针对 056.php:17 的 SQL 注入 POC（CWE-89）。注入点为查询参数 mtxMessage，其值未经有效净化即进入 SQL 查询汇点。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /056）：符合 CWE-89（SQL 注入）。漏洞位于 056.php:17，外部输入来自查询参数 mtxMessage，source→sink 链在给定代码范围内静态闭合，未发现有效净化或参数化查询；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。脚本中的 curl 命令需人工替换 TARGET 后在授权环境手动执行；禁止对生产环境或未授权目标使用。request.http 中的 Content-Length 按载荷字节数给出，实际发送时可由客户端自动计算。

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
| safety_guard | 安全防护 | 3.25 | 是 |
| surface_mapper | 攻击面测绘 | 8.92 | 是 |
| deep_finder | LLM 深挖 | 3.9 | 是 |
| candidate_screener | 候选筛选 | 3.26 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.43 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.2 | 是 |
| coordinator | 管线协调 | 6.36 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
