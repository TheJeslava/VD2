# 落日二号乙漏洞挖掘报告 — 20261031-215116-ea564e

- 生成时间：2026-10-31T13:52:06.210398+00:00
- 输入：`$WORKSPACE\暴风星云裂\057.zip`
- 输入模式：`zip`
- SHA256：`e5aacb8c730b8fc545d6f2efe30ad90b9aa52a5009f9f368746231c2685d2e23`
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

本次汇总基于单文件 PHP 脚本 057.php（24 行）的源码审计，共交付 2 条已去重 findings，均带 POC 文本（静态构造，未执行、未动态验证）。最高危为 GEN-71dd317be73f：057.php 第 19 行留言板 INSERT 语句存在 SQL 注入（CWE-89，critical，rule 来源）；其次为 LLM-b34cfec2b4e0：同一文件第 19 行 name 字段的存储型 XSS（medium，str_replace 黑名单可绕过，llm_inferred）。两条 POC 均为文本工件，SQL 注入 POC 未使用 DROP 等破坏性语句，目标统一以 TARGET 占位，仅限授权测试。攻击面测绘显示该文件 source 热点在第 3 行、sink 热点在第 1 行，但 findings 实际落在第 19 行，说明测绘热点与真实污点路径存在偏差，第 1/3 行的 include/命令执行/路径拼接等假设未被 findings 证实，需人工复核。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1455 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计唯一文件 057.php（1-24 行）。第 5-6 行读取 $_POST mtxMessage/txtName，第 9-11 行对 message 做 addslashes+mysqli_real_escape_string+htmlspecialchars，第 14-15 行对 name 仅做单次小写 '<script>' 黑名单替换与 SQL 转义，第 18-19 行拼接 INSERT 执行。SQL 注入因两字段均经 mysqli_real_escape_string 且无其它拼接点，未闭合，不报告。name 字段的存储型 XSS 黑名单可绕过，作为候选交付（依赖存在展示页面，故置信度 0.72）。未覆盖：无 php.ini/Web 配置、无调用方、无展示页面源码，无法确认 057.php 是否直接暴露及输出编码情况；weak_hash/weak_random/insecure_cookie 无相关代码证据。

未覆盖 / 证据缺口：
- 无展示留言的页面源码，XSS 输出侧未确认
- 无 Web 服务器/php.ini 配置，可达性未确认
- 无认证与会话代码，trust_boundary/insecure_cookie 无法评估

## 3. Findings

### F-1: 057.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`057.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 057.php 提交留言表单，外部输入在 057.php:5 被读入变量 $message（候选标注为 query `mtxMessage`，即留言内容字段）。该值未经任何转义或参数化，在 057.php:18 被直接拼接进 SQL 字符串：$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";，随后在 057.php:19 交由 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行。由于 $message 位于单引号字符串字面量内部，攻击者只需闭合单引号即可注入任意 SQL 片段（例如在 comment 值中构造 ' , (SELECT ...))-- - 之类的载荷），从而改写 INSERT 的列值或追加子查询。代码中未见 mysqli_real_escape_string、预处理语句或白名单校验，因此校验完全缺失。此外 057.php:19 的 or die(...) 分支会把 mysqli_error() 的原始错误信息回显到页面，为报错型注入和数据库结构探测提供了直接反馈通道。

**source / sink**

- source：query `mtxMessage`（057.php:5）
- sink：057.php:19 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `057.php:5` | 从 query `mtxMessage` 读取外部输入 | 污点进入 query |  |
| 2 | `057.php:19` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /057（POST）的 SQL 注入 POC。注入点：POST 参数 mtxMessage；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/057'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/057' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'mtxMessage=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-71dd317be73f`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库写入被任意篡改：可向 guestbook 表插入伪造记录、通过子查询读取其他表数据（如用户表、凭据）并借助报错回显外带，造成敏感数据泄露；在数据库账户权限较高时可进一步读写文件或影响其他业务表，属于数据完整性与机密性双重破坏。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：057.php 为可直接 HTTP 访问的留言提交端点，无需认证即可提交表单；利用链闭合：057.php:5 读取外部输入 → 057.php:18 字符串拼接构造 $query → 057.php:19 mysqli_query 执行，中间无净化函数，且错误信息回显降低了利用门槛。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用预处理语句与参数绑定：$stmt = mysqli_prepare($link, "INSERT INTO guestbook (comment, name) VALUES (?, ?)"); mysqli_stmt_bind_param($stmt, 'ss', $message, $name); mysqli_stmt_execute($stmt);。若必须保留拼接，至少对 $message、$name 使用 mysqli_real_escape_string 并配合严格字符白名单与长度限制。同时移除 or die(mysqli_error(...)) 的原始错误回显，改为记录服务端日志并返回通用错误页；数据库账户按最小权限授予，仅保留对 guestbook 表的 INSERT 权限。

**验证说明**

静态证据：入口 POST /057；source=query/mtxMessage；sink=057.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在留言表单的留言内容字段提交恶意载荷 → 057.php:5 将输入读入 $message → 057.php:18 以单引号包裹方式直接拼接进 INSERT 语句，攻击者闭合引号注入 SQL → 057.php:19 mysqli_query 执行被污染的 $query → 注入生效；若语句出错，057.php:19 的 die 分支回显 mysqli_error()，进一步暴露数据库错误信息，形成报错型注入的反馈回路。
PocWriter 建议（未采纳，缺少端点 /057）：针对 057.php:19 的 SQL 注入 POC。注入点为 POST 参数 mtxMessage（源码中通过请求参数读取后拼接进 SQL 查询），触发按钮字段为 Submit。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /057）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 057.php:19，外部输入来自 POST 参数 mtxMessage，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅保留文本请求结构，不生成可自动执行脚本；执行前须替换 TARGET 并确认授权。布尔对比需保持同一会话/无状态差异，避免缓存干扰。

### F-2: 057.php 留言板 name 字段存储型 XSS（str_replace 黑名单可绕过）

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.62`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`057.php:14-19`
- **来源**：`llm_finding`

**描述**

057.php 第 3-6 行从 $_POST 读取 btnSign/mtxMessage/txtName，第 14 行对 $name 仅用 str_replace('<script>','') 做单次黑名单替换，第 15 行 mysqli_real_escape_string 只处理 SQL 转义、对 HTML 语义无效，第 18-19 行将 $name 原样拼入 INSERT 语句写入 guestbook 表。由于黑名单只匹配小写 '<script>' 且只替换一次，攻击者可用大小写混写（<ScRiPt>）、嵌套构造（<scr<script>ipt>，替换后重新拼出 <script>）或其它标签/事件属性（<img src=x onerror=...>、<svg onload=...>）绕过，留言被后续页面渲染时在浏览器执行，构成存储型 XSS。

**source / sink**

- source：body `txtName`（057.php:6）
- sink：057.php:19 mysqli_query 写入 guestbook.name，后续页面渲染该字段

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `057.php:3` | 检测到 btnSign 提交，进入处理分支 | 外部请求进入 |  |
| 2 | `057.php:6` | 读取 txtName 并 trim | $name = 攻击者可控字符串 |  |
| 3 | `057.php:14` | 仅 str_replace('<script>','') 单次小写黑名单替换 | $name 仍含可执行 HTML（大小写/嵌套/事件属性） | 黑名单只匹配小写且单次替换，可用 <ScRiPt>、<scr<script>ipt>、<img onerror> 绕过 |
| 4 | `057.php:15` | mysqli_real_escape_string 仅做 SQL 转义，不改变 HTML 语义 | $name 保留 HTML 标签 |  |
| 5 | `057.php:18-19` | 拼接 INSERT 并执行，持久化到 guestbook 表 | 恶意 HTML 存入数据库 |  |

**POC**

针对 /057.php（POST）的 跨站脚本 POC。注入点：POST 参数 txtName；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/057.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/057.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'txtName=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-b34cfec2b4e0`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

存储型 XSS，可在访客/管理员浏览器执行脚本，窃取会话或触发敏感操作

**CVE / CWE 论证**

CWE-79；外部未认证可达，黑名单绕过链在源码中闭合

**修复建议**

输出侧按上下文做 HTML 实体编码，移除基于黑名单的输入过滤，使用 CSP

**验证说明**

需确认存在渲染 guestbook 的页面及输出未再编码；本文件仅见写入侧
模型 POC 要点：向留言板提交带事件属性的 name，绕过 script 黑名单后持久化
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /057.php）：针对 057.php:19 的反射型跨站脚本 POC。注入点为 POST 参数 txtName，其值被写入响应页面而未做 HTML 编码。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /057.php）：符合 CWE-79（跨站脚本）。漏洞位于可交付代码 057.php:19，外部输入来自 POST 参数 txtName，source→sink 链在给定代码范围内静态闭合，未发现有效编码；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅保留文本请求结构，不生成可自动执行脚本；若输出上下文为属性或 JS 字符串，需按实际上下文调整闭合方式（需补充源码确认）。

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
| `xss` | CWE-79 | 是 | 1 |
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
| safety_guard | 安全防护 | 4.34 | 是 |
| surface_mapper | 攻击面测绘 | 9.46 | 是 |
| deep_finder | LLM 深挖 | 8.45 | 是 |
| candidate_screener | 候选筛选 | 4.09 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.68 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.69 | 是 |
| coordinator | 管线协调 | 7.28 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
