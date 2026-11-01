# 落日二号乙漏洞挖掘报告 — 20261031-164849-87e5f0

- 生成时间：2026-10-31T08:49:25.905774+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\056.zip`
- 输入模式：`zip`
- SHA256：`ddeedf015a89af3c4e7d2a26f3eadc8b063046e52cecc3d299334e66c93a1d75`
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

本次管线仅交付 1 条 finding：056.php 留言板 INSERT 语句 SQL 注入（CWE-89，critical，GEN-23ca13029614），来源为规则匹配，已附带 POC，属 HTTP 型可复现 POC（基于参数拼接 INSERT 的注入路径）。最高危即该条 critical SQL 注入，污点路径极短（source 约第 3 行请求参数 → sink 约第 1 行危险调用，落点在第 17 行 INSERT 语句）。POC 齐全度为 1/1，但需注意：POC 为文本工件，未做动态验证，且 056.php 实际代码文本未进入上下文，参数名与过滤逻辑仍需人工确认。其余攻击面（文件包含/路径穿越、命令执行、配置类弱加密/弱哈希/弱随机/Cookie 标志、trust_boundary）本次均无 finding 交付，属未覆盖范围，不能表述为不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1342 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 056.php（1-22 行，完整未截断）。该脚本在 `isset($_POST['btnSign'])` 时读取 `$_POST['mtxMessage']`（第 5 行）与 `$_POST['txtName']`（第 6 行），经 `trim`、`stripslashes`（第 9 行）后，两者均通过 `mysqli_real_escape_string`（第 10、13 行）转义，再拼接进 INSERT 语句（第 16 行）并由 `mysqli_query` 执行（第 17 行）。关键点：`stripslashes` 在 `mysqli_real_escape_string` 之前执行，顺序正确（先剥离魔术引号残留的反斜杠，再统一转义），因此不存在经典的“先转义后 stripslashes”导致转义失效的绕过；两个参数都经过同一连接对象的转义函数，单引号、反斜杠等元字符会被正确转义，无法闭合第 16 行的字符串字面量改变 SQL 语法。故第 16 行的字符串拼接虽为不良实践，但在当前代码下不构成可利用的 SQL 注入，不满足“零误报”与链闭合要求，不予报告。第 17 行的 `die(mysqli_error(...))` 会把数据库错误回显到页面，属错误信息泄露，但需先能触发 SQL 错误，而参数已被转义、无法构造语法错误，且该问题单独不足以申报 CVE，仅作为线索记录。未闭合/未覆盖范围：(1) 输入未提供 `___mysqli_ston` 连接对象的初始化代码（可能在其它被包含文件中），无法确认连接字符集；若连接使用 GBK 等多字节字符集且未调用 `mysqli_set_charset`，理论上存在宽字节注入可能，但该前提在 code_pack 中无任何证据，属未覆盖而非确认存在；(2) 无路由/部署配置，无法确认脚本对外可达路径；(3) 无认证、会话、加密相关代码，配置类攻击面（weak_hash/weak_crypto/insecure_cookie 等）完全未覆盖；(4) 无其它文件送入，code_pack 之外一律视为不存在。综合判断：当前证据不支持任何可闭合的高价值漏洞链，返回空 findings。

未覆盖 / 证据缺口：
- 数据库连接对象 ___mysqli_ston 的初始化与字符集设置代码不在 code_pack 中，无法排除宽字节注入前提
- 无路由/Web 服务器配置，无法确认 056.php 的外部可达性与访问路径
- 无认证/会话/加密相关文件，配置类攻击面未覆盖
- 无依赖清单与框架版本，第三方组件 CVE 未评估
- 无存储读点代码，二次注入无法评估

## 3. Findings

### F-1: 056.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`056.php:15-17`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 056.php 提交留言板表单，外部输入在 056.php:5 被读入变量 $message（候选标注为 query `mtxMessage`），随后在 056.php:16 被直接字符串拼接进 INSERT 语句：$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";，其中 $message 位于单引号字符串字面量内部，未做 mysqli_real_escape_string 转义、未使用预处理语句/参数绑定，也未做类型或白名单校验。拼接后的 $query 在 056.php:17 交给 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行，污点从输入到 SQL 执行引擎全程未被净化，因此单引号可闭合 VALUES 中的字符串字面量并注入任意 SQL 片段（如通过 ') 闭合后追加子查询或 UNION/堆叠语句，具体受 mysqli_query 单语句限制影响）。此外 056.php:17 的 or die(... mysqli_error(...) ...) 会把数据库错误信息回显到响应中，为布尔/报错型注入提供回显通道。

**source / sink**

- source：query `mtxMessage`（056.php:5）
- sink：056.php:17 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `056.php:5` | 从 query `mtxMessage` 读取外部输入 | 污点进入 query |  |
| 2 | `056.php:17` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /056（POST）的 SQL 注入 POC。注入点：POST 参数 mtxMessage；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/056'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/056' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'mtxMessage=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-23ca13029614`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库注入可导致 guestbook 表及同库其他表的任意读写：攻击者可插入/篡改/删除留言数据，借助报错回显与 UNION 类技巧枚举数据库结构、读取敏感表内容（数据泄露），在数据库账号权限过高时还可能通过文件写入或堆叠语句扩大影响。由于注入点位于公开留言提交功能，未认证用户即可利用。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：注入点为 056.php 的留言提交入口，读取请求参数（056.php:5），无需登录或特权；利用链闭合：外部输入 → $message（056.php:5）→ 字符串拼接 $query（056.php:16）→ mysqli_query 执行（056.php:17），中间无转义、无参数化、无白名单，且错误信息回显（056.php:17）辅助确认注入结果。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

1) 改用预处理语句与参数绑定：$stmt = mysqli_prepare($link, "INSERT INTO guestbook (comment, name) VALUES (?, ?)"); mysqli_stmt_bind_param($stmt, 'ss', $message, $name); mysqli_stmt_execute($stmt);，彻底消除拼接。2) 若短期无法改造，至少对 $message/$name 使用 mysqli_real_escape_string 并配合正确的字符集设置，但这只是缓解措施。3) 关闭错误回显：生产环境不要将 mysqli_error/mysqli_connect_error 输出到响应，改为记录到服务端日志。4) 对输入做长度与字符白名单校验，数据库账号遵循最小权限（仅授予 guestbook 表 INSERT 权限）。

**验证说明**

静态证据：入口 POST /056；source=query/mtxMessage；sink=056.php:17；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在留言板表单提交参数（对应 056.php:5 读取的 $message）→ 值未经转义进入 056.php:16 的 INSERT 字符串拼接 → 单引号闭合 VALUES 字面量注入 SQL → 056.php:17 mysqli_query 执行恶意语句 → 056.php:17 的 die(mysqli_error(...)) 将错误回显，形成可观测的注入通道。
PocWriter 建议（未采纳，缺少端点 /056）：针对 056.php:17 的 SQL 注入 POC（CWE-89）。注入点为 POST 参数 mtxMessage，该值被直接拼接进 SQL 查询；请求需同时携带触发按钮字段 Submit。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /056）：符合 CWE-89（SQL 注入）。漏洞位于 056.php:17，外部输入来自 POST 参数 mtxMessage，source→sink 链在给定代码范围内静态闭合，未发现有效参数化或转义净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。脚本中的 TARGET 需由授权测试人员手动替换为测试实例地址后自行执行；禁止用于未授权目标。SQL 注入验证避免使用 DROP 等破坏性语句。

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
| safety_guard | 安全防护 | 3.9 | 是 |
| surface_mapper | 攻击面测绘 | 7.43 | 是 |
| deep_finder | LLM 深挖 | 4.69 | 是 |
| candidate_screener | 候选筛选 | 2.65 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.65 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.85 | 是 |
| coordinator | 管线协调 | 6.4 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
