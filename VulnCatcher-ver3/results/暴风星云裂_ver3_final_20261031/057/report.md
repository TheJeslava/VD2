# 落日二号乙漏洞挖掘报告 — 20261031-014519-a11bfa

- 生成时间：2026-10-30T17:45:52.625899+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\057.zip`
- 输入模式：`zip`
- SHA256：`e5aacb8c730b8fc545d6f2efe30ad90b9aa52a5009f9f368746231c2685d2e23`
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

本次汇总仅含 1 条已去重 finding：057.php 留言板 INSERT 语句 SQL 注入（CWE-89，critical，rule 来源，已附 POC），是本次最高危且唯一交付项。该结论基于规则命中，POC 为文本工件，未做动态验证。其余攻击面（文件包含/路径穿越、命令执行、弱哈希/弱随机、Cookie 标志位、硬编码凭据、鉴权边界）在 surface_notes 中被列为待核查点，但无对应 finding，属覆盖缺口而非已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1455 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 057.php（1-24 行，完整未截断）。该脚本为 DVWA 风格的留言板写入片段：入口为 POST 参数 btnSign/mtxMessage/txtName（第 3、5、6 行），汇点为第 18-19 行拼接 INSERT 语句并 mysqli_query 执行。逐跳核对：$message 经 trim→strip_tags→addslashes→mysqli_real_escape_string→htmlspecialchars（第 5、9、10、11 行），$name 经 trim→str_replace('<script>')→mysqli_real_escape_string（第 6、14、15 行），两者在进入第 18 行字符串拼接前均已通过 mysqli_real_escape_string 转义引号与反斜杠，单引号包裹的字符串字面量无法被闭合，未发现可绕过该转义的编码/字符集前置条件证据（无 SET NAMES / 字符集设置代码可见），因此不构成可闭合的 SQL 注入链。第 14 行 str_replace 仅删除字面 '<script>'，属弱 XSS 过滤，但第 11 行对 $message 做了 htmlspecialchars、$name 未做 HTML 编码，理论上存在存储型 XSS 可能（如 <img src=x onerror=>、<SCRIPT>、<script > 等变体），但本 code_pack 只包含写入片段，缺少读取/渲染留言的页面（存储读点与输出汇点），无法闭合「存储写点→存储读点→危险输出汇点」三要素，按规则不报告二次注入/存储型 XSS。未发现命令执行、文件包含、反序列化、SSRF、路径穿越等汇点；无 setcookie/session/md5/rand/硬编码凭据代码，配置类候选均无证据。输入中未出现诱导性文本，无 prompt_injection 证据。

未覆盖 / 证据缺口：
- 缺少留言读取/展示页面，无法验证 $name 的存储型 XSS 是否在输出端未编码（潜在线索，未闭合）
- 缺少数据库连接与字符集配置（___mysqli_ston 初始化处），无法排除宽字节/字符集导致的 mysqli_real_escape_string 绕过
- 无端点清单与部署配置，无法确认实际路由与 allow_url_include 等运行时条件
- 无认证/会话代码，无法评估鉴权边界

## 3. Findings

### F-1: 057.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`057.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 057.php 提交留言内容（源码中对应变量 $message，来自 query 参数 mtxMessage，见 057.php:5），该值未经任何转义或参数化即被拼接进 SQL 语句：057.php:18 构造 $query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );",随后在 057.php:19 通过 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行。由于 $message 被直接放入单引号字符串字面量中，攻击者只需闭合单引号即可注入任意 SQL 片段（例如在 comment 值中构造 ' , (SELECT ...))-- - 之类的载荷），从而改变 INSERT 的语义或追加子查询。代码中未见 mysqli_real_escape_string、预处理语句或类型白名单，校验完全缺失，因此污点从 mtxMessage 参数直达 mysqli_query 汇点，链路闭合。

**source / sink**

- source：query `mtxMessage`（057.php:5）
- sink：057.php:19 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `057.php:5` | 从 query `mtxMessage` 读取外部输入 | 污点进入 query |  |
| 2 | `057.php:19` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /057（ANY）的 SQL 注入 POC。注入点：ANY 参数 mtxMessage；payload 使用 TARGET 占位符。

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

可对后端 MySQL 数据库执行任意 INSERT/子查询语句：篡改或伪造留言数据、通过子查询读取其他表（如用户表）内容并写入 guestbook 造成数据泄露、在数据库权限允许时写入任意表；错误信息经 die() 回显（mysqli_error）还会泄露库结构，为进一步攻击提供情报。属于数据完整性与机密性破坏，严重级别 critical。

**CVE / CWE 论证**

CWE-89（SQL 注入）：外部可控输入 $message 未经参数化直接拼接进 SQL 并在 057.php:19 执行，满足外部可达（HTTP 参数 mtxMessage）、无需认证（留言板提交接口默认匿名可访问）、利用链闭合（source→拼接→mysqli_query）三要素。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

1) 改用预处理语句：$stmt = $mysqli->prepare("INSERT INTO guestbook (comment, name) VALUES (?, ?)"); $stmt->bind_param('ss', $message, $name); $stmt->execute(); 2) 若暂不能改造，至少对 $message/$name 使用 mysqli_real_escape_string 并配合正确的字符集设置；3) 关闭错误详情回显，将 mysqli_error 写入服务端日志而非输出到页面；4) 对输入长度与字符集做白名单校验，数据库账号遵循最小权限（仅 INSERT 权限）。

**验证说明**

静态证据：入口 ANY /057；source=query/mtxMessage；sink=057.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在留言提交请求中设置参数 mtxMessage（057.php:5 读取为 $message）→ 057.php:18 将 $message 原样拼入 INSERT 语句字符串 → 057.php:19 mysqli_query 执行拼接后的 $query，注入的 SQL 片段随语句一起执行；失败时 die() 回显数据库错误，进一步暴露结构信息。
PocWriter 建议（未采纳，缺少端点 /057）：针对 057.php:19 的 SQL 注入 POC（CWE-89）。外部输入来自 HTTP 查询参数 mtxMessage，在未做有效净化的情况下被拼接进 SQL 语句执行。POC 使用布尔恒真载荷 ' OR '1'='1 验证注入点，目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /057）：符合 CWE-89（SQL 注入）。漏洞位于 057.php:19，外部输入来自查询参数 mtxMessage，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权目标并确认授权范围。原始草稿中的 poc.sh 含 curl 命令，仅作参考文本，不应自动运行；request.http 中的 Content-Length 与 GET 请求体不匹配，已改为无请求体的 GET 形式。禁止使用 DROP、写文件、堆叠查询等破坏性载荷。

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
| safety_guard | 安全防护 | 2.02 | 是 |
| surface_mapper | 攻击面测绘 | 8.52 | 是 |
| deep_finder | LLM 深挖 | 3.94 | 是 |
| candidate_screener | 候选筛选 | 2.29 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.14 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.52 | 是 |
| coordinator | 管线协调 | 5.62 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
