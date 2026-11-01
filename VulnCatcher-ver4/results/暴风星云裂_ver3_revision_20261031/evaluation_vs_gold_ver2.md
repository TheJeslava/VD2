# 暴风星云裂 ver3 评估（暴风星云裂_ver3_revision_20261031）

本报告将 finding 与 20 个金标类别逐样本比较；finding 仍是 candidate，POC 只做静态契约检查，未执行网络请求。

## 指标

| 口径 | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| 样本类别严格匹配 | 39 | 11 | 19 | 78.00% | 67.24% | 72.22% |
| 仅判断样本是否有 finding | 50 | 0 | 8 | 100.00% | 86.21% | 92.59% |

数据集 58 个样本全部是正例，不能估计 TN、特异度或常规二分类 accuracy。

## 20 类别 low/medium/high 正确情况

| 类别 | low | medium | high |
|---|---|---|---|
| API 信息泄露 | 正确（002） | 误报/漏报（003: api_info_disclosure,xss） | 误报/漏报（001: api_info_disclosure） |
| 认证绕过 | 漏报（005） | 漏报（006） | 漏报（004） |
| 越权/IDOR | 正确（008） | 误报/漏报（009: sql_injection） | 漏报（007） |
| 暴力破解 | 正确（011） | 正确（012） | 误报/漏报（010: sql_injection,weak_crypto,xss） |
| 验证码绕过 | 正确（014） | 正确（015） | 正确（013） |
| 弱加密 | 正确（017） | 正确（018） | 正确（016） |
| CSP 配置缺陷 | 正确（020） | 正确（021） | 正确（019） |
| CSRF | 正确（023） | 正确（024） | 误报/漏报（022: path_traversal,sql_injection,weak_crypto） |
| 命令注入 | 正确（026） | 正确（027） | 正确（025） |
| 路径穿越/LFI | 漏报（029） | 正确（030） | 正确（028） |
| 客户端 JavaScript 校验绕过 | 误报/漏报（032: weak_crypto） | 正确（033） | 正确（031） |
| 开放重定向 | 正确（035） | 正确（036） | 正确（034） |
| 盲 SQL 注入 | 正确（038） | 正确（039） | 正确（037） |
| SQL 注入 | 正确（041） | 正确（042） | 漏报（040） |
| 文件上传 | 正确（044） | 正确（045） | 正确（043） |
| 弱 ID/可预测会话标识 | 正确（047） | 正确（048） | 正确（046） |
| DOM 型 XSS | 漏报（050） | 误报/漏报（051: open_redirect） | 漏报（049） |
| 反射型 XSS | 正确（053） | 正确（054） | 正确（052） |
| 存储型 XSS | 误报/漏报（056: sql_injection） | 误报/漏报（057: sql_injection） | 误报/漏报（055: sql_injection） |
| 二次注入 | 部分（058: auth_bypass,csrf,sql_injection,weak_id） | - | - |

## POC 静态契约结果

共检查 114 个 POC：not_executable=16, static_consistent=91, static_inconsistent=7。

静态一致不等于漏洞已验证：未执行目标服务、未重放请求、未观察响应差异。

| 样本 | finding | 状态 | 原因 |
|---|---|---|---|
| 008 | SEM-e3f1dc6ea55d | static_inconsistent | finding 来源为 Cookie，但 POC 未发送 Cookie 请求头 |
| 008 | LLM-3ee4fdec5d75 | static_inconsistent | HTTP POC 未使用 TARGET 占位符；请求未包含 finding 端点 /008.php；请求未体现 HTTP 方法 GET |
| 010 | SEM-949d40928ae7 | not_executable |  |
| 011 | SEM-2ea8df0ef3b9 | not_executable |  |
| 012 | SEM-0ce3358fa05b | not_executable |  |
| 013 | SEM-0bafba96288b | not_executable |  |
| 014 | SEM-f257349cbc66 | not_executable |  |
| 015 | SEM-81919fa4d087 | not_executable |  |
| 016 | SEM-8ca5b94d5c6d | not_executable |  |
| 017 | SEM-2e4335a5c995 | not_executable |  |
| 018 | LLM-86c6c58e13d2 | not_executable |  |
| 018 | SEM-1f3cfc0b6797 | not_executable |  |
| 022 | SEM-f7415d28d8c9 | not_executable |  |
| 023 | SEM-de6429df0eff | not_executable |  |
| 024 | SEM-23ce27f2da1c | not_executable |  |
| 032 | SEM-991eb6123bf3 | not_executable |  |
| 046 | SEM-19354a0facf2 | static_inconsistent | finding 来源为 Cookie，但 POC 未发送 Cookie 请求头 |
| 046 | LLM-e9310d5416a7 | not_executable |  |
| 046 | SEM-7da0188b59a9 | not_executable |  |
| 047 | SEM-f8846702c19b | static_inconsistent | finding 来源为 Cookie，但 POC 未发送 Cookie 请求头 |
| 048 | SEM-26658112c975 | static_inconsistent | finding 来源为 Cookie，但 POC 未发送 Cookie 请求头 |
| 058 | SEM-381e6544791c | static_inconsistent | finding 来源为 Cookie，但 POC 未发送 Cookie 请求头 |
| 058 | SEM-84e9d7c625f8 | static_inconsistent | finding 来源为 Cookie，但 POC 未发送 Cookie 请求头 |

## 误报/漏报归因

| 样本 | 金标类别 | finding 类型 | 结论 | 核心原因 |
|---|---|---|---|---|
| 001 | API 信息泄露（high） | api_info_disclosure | 误报/漏报 | 类型不匹配（实际：api_info_disclosure）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 003 | API 信息泄露（medium） | api_info_disclosure, xss | 误报/漏报 | 类型不匹配（实际：api_info_disclosure, xss）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 004 | 认证绕过（high） | 无 | 漏报 | 类别专项规则或模型上下文不足 |
| 005 | 认证绕过（low） | 无 | 漏报 | 类别专项规则或模型上下文不足 |
| 006 | 认证绕过（medium） | 无 | 漏报 | 类别专项规则或模型上下文不足 |
| 007 | 越权/IDOR（high） | 无 | 漏报 | 对象授权关系需要业务主体/对象对比，LLM 未获得足够业务上下文 |
| 009 | 越权/IDOR（medium） | sql_injection | 误报/漏报 | 类型不匹配（实际：sql_injection）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 010 | 暴力破解（high） | sql_injection, weak_crypto, xss | 误报/漏报 | 类型不匹配（实际：sql_injection, weak_crypto, xss）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 022 | CSRF（high） | path_traversal, sql_injection, weak_crypto | 误报/漏报 | 类型不匹配（实际：path_traversal, sql_injection, weak_crypto）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 029 | 路径穿越/LFI（low） | 无 | 漏报 | include/路径规范化链未被当前规则稳定识别 |
| 032 | 客户端 JavaScript 校验绕过（low） | weak_crypto | 误报/漏报 | 类型不匹配（实际：weak_crypto）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 040 | SQL 注入（high） | 无 | 漏报 | 类别专项规则或模型上下文不足 |
| 049 | DOM 型 XSS（high） | 无 | 漏报 | 客户端脚本未进入有效 source→sink 审计路径，缺少 JS 专项核查 |
| 050 | DOM 型 XSS（low） | 无 | 漏报 | 客户端脚本未进入有效 source→sink 审计路径，缺少 JS 专项核查 |
| 051 | DOM 型 XSS（medium） | open_redirect | 误报/漏报 | 类型不匹配（实际：open_redirect）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 055 | 存储型 XSS（high） | sql_injection | 误报/漏报 | 类型不匹配（实际：sql_injection）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 056 | 存储型 XSS（low） | sql_injection | 误报/漏报 | 类型不匹配（实际：sql_injection）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 057 | 存储型 XSS（medium） | sql_injection | 误报/漏报 | 类型不匹配（实际：sql_injection）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 058 | 二次注入（low） | auth_bypass, csrf, sql_injection, weak_id | 部分命中（未标为二次注入） | 类型不匹配（实际：auth_bypass, csrf, sql_injection, weak_id）；通用模式偏置/Prompt 未强制按金标根因分类 |

## 误报过滤规则

1. 只有存在可定位 source→sink 链、同一请求入口和真实代码行号时，才保留通用注入 finding。
2. session、Cookie、Referer、Authorization 等来源必须与 POC 的实际请求载体一致；生成 param/query 代替非参数来源时过滤。
3. 认证绕过只能在存在认证决策点且攻击者输入可控时成立；弱算法是根因时归类为 weak_crypto，不把影响冒充根因。
4. SQL 注入必须同时满足可控表达式、SQL 拼接/执行 sink 和可达端点；只有字符串/数据库调用没有污点链时过滤。
5. 业务语义类别（BAC、暴力破解、验证码、弱 ID、CSRF）需要状态/主体/对象对比证据，通用模式命中不得升级为该类别。
6. POC 的方法、端点、参数或请求头必须与 finding 的 source 对齐；契约失败的 finding 进入人工复核。

## 漏报补强核查清单

| 类别 | 补强检查 | 所需证据 |
|---|---|---|
| API 信息泄露 | 逐字段检查响应/序列化输出与权限边界，区分信息泄露和批量赋值 | 对应源码、跨文件调用/请求与可观察结果 |
| 认证绕过 | 追踪认证条件、默认值、状态变量和密码/令牌比较 | 对应源码、跨文件调用/请求与可观察结果 |
| 越权/IDOR | 构造不同用户/对象 ID 对比，确认服务端授权而非仅有 SQL 查询 | 对应源码、跨文件调用/请求与可观察结果 |
| 暴力破解 | 检查失败计数、速率限制、锁定、验证码与 IP/账户维度 | 对应源码、跨文件调用/请求与可观察结果 |
| 验证码绕过 | 串联 step 参数、session/client 状态和最终改密请求 | 对应源码、跨文件调用/请求与可观察结果 |
| 弱加密 | 枚举算法、模式、密钥来源与令牌生成/验证路径 | 对应源码、跨文件调用/请求与可观察结果 |
| CSP 配置缺陷 | 检查响应头、nonce/hash、脚本来源和策略是否实际生效 | 对应源码、跨文件调用/请求与可观察结果 |
| CSRF | 枚举所有状态改变请求并检查 token、Origin/Referer、SameSite | 对应源码、跨文件调用/请求与可观察结果 |
| 命令注入 | 确认输入进入命令参数/命令字符串，区分环境变量和 argv | 对应源码、跨文件调用/请求与可观察结果 |
| 路径穿越/LFI | 追踪 include/file_get_contents/路径规范化和目录限制 | 对应源码、跨文件调用/请求与可观察结果 |
| 客户端 JavaScript 校验绕过 | 审计客户端校验与服务端重复校验，记录可直接构造的请求 | 对应源码、跨文件调用/请求与可观察结果 |
| 开放重定向 | 确认 Location/redirect sink 使用可控 URL 且无 allowlist | 对应源码、跨文件调用/请求与可观察结果 |
| 盲 SQL 注入 | 保留布尔/时间差异证据，区分盲注与普通错误回显 | 对应源码、跨文件调用/请求与可观察结果 |
| SQL 注入 | 验证输入到 SQL 拼接/执行的完整链和参数名 | 对应源码、跨文件调用/请求与可观察结果 |
| 文件上传 | 检查扩展名、MIME、内容、存储路径及可执行权限 | 对应源码、跨文件调用/请求与可观察结果 |
| 弱 ID/可预测会话标识 | 跨请求比较 ID/会话标识可预测性与授权检查 | 对应源码、跨文件调用/请求与可观察结果 |
| DOM 型 XSS | 审计 DOM source→sink、URL fragment 和客户端执行路径 | 对应源码、跨文件调用/请求与可观察结果 |
| 反射型 XSS | 追踪同请求参数到响应输出的反射位置与编码 | 对应源码、跨文件调用/请求与可观察结果 |
| 存储型 XSS | 跨请求追踪存储点到 HTML/属性/JS sink 的编码上下文 | 对应源码、跨文件调用/请求与可观察结果 |
| 二次注入 | 串联注册写入→登录会话→改密读取，确认二次注入与数据库字符集 | 对应源码、跨文件调用/请求与可观察结果 |

## 初始版本缺陷与 ver2 改动

初始版本关闭确定性规则候选，主要依赖一次 LLM DeepFinder，导致上下文截断、类别覆盖不均和类型根因/影响混淆；POC 只写不跑且没有 source/请求契约检查。
ver3 在 ver2 基础上加入 API、验证码、CSP、弱 ID、客户端校验、CSRF、弱加密等语义候选，修正 PHP 常量覆盖造成的旧污点残留，并要求筛选器保护有明确源码证据的语义候选；同时保留 POC 静态契约校验。改进提升了类别覆盖，但未覆盖全部路径穿越、DOM/存储型 XSS 和二次注入链。
ver3 的另一轮筛选器反证试验把模型解释文本直接用作丢弃规则，实测严格匹配从 41/58 降至 33/58，表明自然语言反证正则过于脆弱；最终结果采用不含该规则的 ver3_revision 批次。POC 仍未在隔离目标上动态执行。
