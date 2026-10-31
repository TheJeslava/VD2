# 落日二号乙漏洞挖掘报告 — 20261101-025658-d43216

- 生成时间：2026-10-31T18:56:58.847872+00:00
- 输入：`D:\wlaqdzy\VD2\落日二号乙-ver5\docs\experiments\logic_20261101\logic_lab_sources.zip`
- 输入模式：`zip`
- SHA256：`7db818cd5693565f3e4870103a5e5c3476cb19a96731f0c72f51447570130090`
- 文件：3（文本 3）
- 语言：python(3)
- 框架：未识别
- 端点：0
- 版本：1.5.0-ver5
- 严重度档位：`high`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

共发现 4 条候选 finding，覆盖 2 种漏洞类型；4 条已生成 POC。管线未执行 POC、未搭建沙箱，所有结论均为 candidate，需人工/授权环境复核。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 未执行：LLM 未启用

## 3. Findings

### F-1: 隐性逻辑：修改密码前必须由服务端记录当前会话已通过验证；仅针对本次操作。

- **类型**：`business_logic` / CWE-840
- **严重度**：`high`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `static_candidate`
- **位置**：`vulnerable.py:6-6`
- **来源**：`logic_specialist`

**描述**

存在到达敏感操作的路径，未发现指定业务条件在服务端强制成立；需动态对照验证。

**source / sink**

- source：业务入口及操作者指定的信任边界
- sink：vulnerable.py:6

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `vulnerable.py:4` | scope | def reset_password(body, session, store): |  |
| 2 | `vulnerable.py:6` | operation |     store.change_password(session['user_id'], body['password']) |  |

**POC**

vulnerable.py:6 的业务状态对照验证计划（未执行）

1. **在本地或授权环境准备正常用户、初始业务状态及正常请求。**
预期：同时核对响应与服务端业务状态

2. **仅改变该规则相关的前置步骤、对象归属或边界输入，发送对照请求。**
预期：同时核对响应与服务端业务状态

3. **核对真实数据库/业务状态的变化，不把 HTTP 200 或成功字符串单独作为证明。**
预期：同时核对响应与服务端业务状态

4. **对修复版重复正常及异常请求，保存请求、响应与操作前后状态。**
预期：同时核对响应与服务端业务状态

- POC 目录：`poc/BL-c4d7a718d97e93`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

可能违反所列业务规则；实际影响以受控环境的状态对照实验为准。

**CVE / CWE 论证**

关联 CWE-840；此结果是指定规则下的静态候选，不表示已获 CVE 或已完成动态验证。

**修复建议**

在服务端敏感操作之前强制执行：修改密码前必须由服务端记录当前会话已通过验证；仅针对本次操作。；确保校验与操作使用同一对象、身份和数值。

**验证说明**

未执行目标 POC。规则来源：operator_policy；

### F-2: 隐性逻辑：修改密码前必须检查服务端验证状态，不能信任请求中的 passed_captcha。

- **类型**：`business_logic` / CWE-840
- **严重度**：`high`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `static_candidate`
- **位置**：`vulnerable.py:14-14`
- **来源**：`logic_specialist`

**描述**

存在到达敏感操作的路径，未发现指定业务条件在服务端强制成立；需动态对照验证。

**source / sink**

- source：业务入口及操作者指定的信任边界
- sink：vulnerable.py:14

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `vulnerable.py:10` | scope | def reset_password_client_flag(body, session, store): |  |
| 2 | `vulnerable.py:14` | operation |     store.change_password(session['user_id'], body['password']) |  |

**POC**

vulnerable.py:14 的业务状态对照验证计划（未执行）

1. **在本地或授权环境准备正常用户、初始业务状态及正常请求。**
预期：同时核对响应与服务端业务状态

2. **仅改变该规则相关的前置步骤、对象归属或边界输入，发送对照请求。**
预期：同时核对响应与服务端业务状态

3. **核对真实数据库/业务状态的变化，不把 HTTP 200 或成功字符串单独作为证明。**
预期：同时核对响应与服务端业务状态

4. **对修复版重复正常及异常请求，保存请求、响应与操作前后状态。**
预期：同时核对响应与服务端业务状态

- POC 目录：`poc/BL-9a000ea8a08f5e`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

可能违反所列业务规则；实际影响以受控环境的状态对照实验为准。

**CVE / CWE 论证**

关联 CWE-840；此结果是指定规则下的静态候选，不表示已获 CVE 或已完成动态验证。

**修复建议**

在服务端敏感操作之前强制执行：修改密码前必须检查服务端验证状态，不能信任请求中的 passed_captcha。；确保校验与操作使用同一对象、身份和数值。

**验证说明**

未执行目标 POC。规则来源：operator_policy；

### F-3: 隐性逻辑：本实验禁止用户修改其他用户的订单；服务端身份与持久化订单归属必须相同。

- **类型**：`idor` / CWE-639
- **严重度**：`high`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `static_candidate`
- **位置**：`vulnerable.py:20-20`
- **来源**：`logic_specialist`

**描述**

存在到达敏感操作的路径，未发现指定业务条件在服务端强制成立；需动态对照验证。

**source / sink**

- source：业务入口及操作者指定的信任边界
- sink：vulnerable.py:20

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `vulnerable.py:18` | scope | def update_order(body, session, store): |  |
| 2 | `vulnerable.py:20` | operation |     store.update_order(order['id'], body['memo']) |  |

**POC**

vulnerable.py:20 的业务状态对照验证计划（未执行）

1. **在本地或授权环境准备正常用户、初始业务状态及正常请求。**
预期：同时核对响应与服务端业务状态

2. **仅改变该规则相关的前置步骤、对象归属或边界输入，发送对照请求。**
预期：同时核对响应与服务端业务状态

3. **核对真实数据库/业务状态的变化，不把 HTTP 200 或成功字符串单独作为证明。**
预期：同时核对响应与服务端业务状态

4. **对修复版重复正常及异常请求，保存请求、响应与操作前后状态。**
预期：同时核对响应与服务端业务状态

- POC 目录：`poc/BL-06534c8b875e71`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

可能违反所列业务规则；实际影响以受控环境的状态对照实验为准。

**CVE / CWE 论证**

关联 CWE-639；此结果是指定规则下的静态候选，不表示已获 CVE 或已完成动态验证。

**修复建议**

在服务端敏感操作之前强制执行：本实验禁止用户修改其他用户的订单；服务端身份与持久化订单归属必须相同。；确保校验与操作使用同一对象、身份和数值。

**验证说明**

未执行目标 POC。规则来源：operator_policy；

### F-4: 隐性逻辑：本实验购买数量必须为正整数；传输层验证整数类型，本规则验证正数边界。

- **类型**：`business_logic` / CWE-840
- **严重度**：`high`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `static_candidate`
- **位置**：`vulnerable.py:26-26`
- **来源**：`logic_specialist`

**描述**

存在到达敏感操作的路径，未发现指定业务条件在服务端强制成立；需动态对照验证。

**source / sink**

- source：业务入口及操作者指定的信任边界
- sink：vulnerable.py:26

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `vulnerable.py:24` | scope | def purchase(body, session, store): |  |
| 2 | `vulnerable.py:26` | operation |     store.purchase(session['user_id'], quantity) |  |

**POC**

vulnerable.py:26 的业务状态对照验证计划（未执行）

1. **在本地或授权环境准备正常用户、初始业务状态及正常请求。**
预期：同时核对响应与服务端业务状态

2. **仅改变该规则相关的前置步骤、对象归属或边界输入，发送对照请求。**
预期：同时核对响应与服务端业务状态

3. **核对真实数据库/业务状态的变化，不把 HTTP 200 或成功字符串单独作为证明。**
预期：同时核对响应与服务端业务状态

4. **对修复版重复正常及异常请求，保存请求、响应与操作前后状态。**
预期：同时核对响应与服务端业务状态

- POC 目录：`poc/BL-5af617653bcca5`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

可能违反所列业务规则；实际影响以受控环境的状态对照实验为准。

**CVE / CWE 论证**

关联 CWE-840；此结果是指定规则下的静态候选，不表示已获 CVE 或已完成动态验证。

**修复建议**

在服务端敏感操作之前强制执行：本实验购买数量必须为正整数；传输层验证整数类型，本规则验证正数边界。；确保校验与操作使用同一对象、身份和数值。

**验证说明**

未执行目标 POC。规则来源：operator_policy；

## 隐性逻辑专属判定（LogicAnalyzer）

详细证据、缺口与对照验证步骤见 `logic_analysis.json`。未执行目标 POC。
`guarded` 只表示指定局部规则有保护，不代表应用安全；`needs_context` 不算已检出漏洞。

| 规则 | 位置 | 状态 | 理由 |
|---|---|---|---|
| 修改密码前必须由服务端记录当前会话已通过验证；仅针对本次操作。 | `vulnerable.py:6` | candidate | 存在到达敏感操作的路径，未发现指定业务条件在服务端强制成立；需动态对照验证。 |
| 修改密码前必须检查服务端验证状态，不能信任请求中的 passed_captcha。 | `vulnerable.py:14` | candidate | 存在到达敏感操作的路径，未发现指定业务条件在服务端强制成立；需动态对照验证。 |
| 本实验禁止用户修改其他用户的订单；服务端身份与持久化订单归属必须相同。 | `vulnerable.py:20` | candidate | 存在到达敏感操作的路径，未发现指定业务条件在服务端强制成立；需动态对照验证。 |
| 本实验购买数量必须为正整数；传输层验证整数类型，本规则验证正数边界。 | `vulnerable.py:26` | candidate | 存在到达敏感操作的路径，未发现指定业务条件在服务端强制成立；需动态对照验证。 |
| 修改密码前必须由服务端记录当前会话已通过验证；仅针对本次操作。 | `fixed.py:7` | guarded | 所有已建模的可达操作路径均受指定条件保护；仅表示此规则的局部检查成立。 |
| 修改密码前必须检查服务端验证状态，不能信任请求中的 passed_captcha。 | `fixed.py:15` | guarded | 所有已建模的可达操作路径均受指定条件保护；仅表示此规则的局部检查成立。 |
| 本实验禁止用户修改其他用户的订单；服务端身份与持久化订单归属必须相同。 | `fixed.py:24` | guarded | 所有已建模的可达操作路径均受指定条件保护；仅表示此规则的局部检查成立。 |
| 本实验购买数量必须为正整数；传输层验证整数类型，本规则验证正数边界。 | `fixed.py:32` | guarded | 所有已建模的可达操作路径均受指定条件保护；仅表示此规则的局部检查成立。 |
| 修改密码前必须由服务端记录当前会话已通过验证；仅针对本次操作。 | `missing_context.py:8` | needs_context | 当前源码不足以判定该业务条件是否有效保护操作。 |
| 本实验禁止用户修改其他用户的订单；服务端身份与持久化订单归属必须相同。 | `missing_context.py:14` | needs_context | 当前源码不足以判定该业务条件是否有效保护操作。 |
| 本实验购买数量必须为正整数；传输层验证整数类型，本规则验证正数边界。 | `missing_context.py:20` | needs_context | 当前源码不足以判定该业务条件是否有效保护操作。 |

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
| `blind_sql_injection` | CWE-89 |  | 0 |
| `ssrf` | CWE-918 | 是 | 0 |
| `path_traversal` | CWE-22 | 是 | 0 |
| `deserialization` | CWE-502 | 是 | 0 |
| `ssti` | CWE-1336 | 是 | 0 |
| `auth_bypass` | CWE-287 | 是 | 0 |
| `idor` | CWE-639 | 是 | 1 |
| `xxe` | CWE-611 | 是 | 0 |
| `xss` | CWE-79 | 是 | 0 |
| `business_logic` | CWE-840 | 是 | 3 |
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
| safety_guard | 安全防护 | 0.0 | 否 |
| surface_mapper | 攻击面测绘 | 0.0 | 否 |
| deep_finder | LLM 深挖 | 0.0 | 否 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| logic_analyzer | 隐性逻辑判定 | 0.02 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 0.0 | 否 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
