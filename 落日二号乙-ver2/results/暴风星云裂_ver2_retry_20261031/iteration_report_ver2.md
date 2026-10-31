# 暴风星云裂 ver2 评估（暴风星云裂_ver2_retry_20261031）

本报告将 finding 与 20 个金标类别逐样本比较；finding 仍是 candidate，POC 只做静态契约检查，未执行网络请求。

## 指标

| 口径 | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| 样本类别严格匹配 | 15 | 18 | 43 | 45.45% | 25.86% | 32.97% |
| 仅判断样本是否有 finding | 33 | 0 | 25 | 100.00% | 56.90% | 72.53% |

数据集 58 个样本全部是正例，不能估计 TN、特异度或常规二分类 accuracy。

## 20 类别 low/medium/high 正确情况

| 类别 | low | medium | high |
|---|---|---|---|
| API 信息泄露 | 漏报（002） | 漏报（003） | 漏报（001） |
| 认证绕过 | 漏报（005） | 漏报（006） | 漏报（004） |
| 越权/IDOR | 正确（008） | 误报/漏报（009: sql_injection） | 漏报（007） |
| 暴力破解 | 误报/漏报（011: sql_injection） | 误报/漏报（012: sql_injection） | 误报/漏报（010: sql_injection,xss） |
| 验证码绕过 | 误报/漏报（014: sql_injection） | 误报/漏报（015: auth_bypass,sql_injection） | 误报/漏报（013: auth_bypass,sql_injection） |
| 弱加密 | 漏报（017） | 误报/漏报（018: auth_bypass） | 漏报（016） |
| CSP 配置缺陷 | 误报/漏报（020: path_traversal,xss） | 误报/漏报（021: path_traversal） | 误报/漏报（019: path_traversal） |
| CSRF | 误报/漏报（023: sql_injection） | 误报/漏报（024: business_logic,sql_injection） | 误报/漏报（022: path_traversal,sql_injection） |
| 命令注入 | 正确（026） | 正确（027） | 正确（025） |
| 路径穿越/LFI | 漏报（029） | 漏报（030） | 正确（028） |
| 客户端 JavaScript 校验绕过 | 漏报（032） | 漏报（033） | 漏报（031） |
| 开放重定向 | 漏报（035） | 漏报（036） | 漏报（034） |
| 盲 SQL 注入 | 正确（038） | 正确（039） | 正确（037） |
| SQL 注入 | 正确（041） | 正确（042） | 正确（040） |
| 文件上传 | 正确（044） | 正确（045） | 正确（043） |
| 弱 ID/可预测会话标识 | 漏报（047） | 漏报（048） | 漏报（046） |
| DOM 型 XSS | 漏报（050） | 漏报（051） | 漏报（049） |
| 反射型 XSS | 漏报（053） | 漏报（054） | 正确（052） |
| 存储型 XSS | 误报/漏报（056: sql_injection） | 误报/漏报（057: sql_injection） | 误报/漏报（055: sql_injection） |
| 二次注入 | 部分（058: auth_bypass,sql_injection） | - | - |

## POC 静态契约结果

共检查 57 个 POC：static_consistent=57。

静态一致不等于漏洞已验证：未执行目标服务、未重放请求、未观察响应差异。

被动工件复核：57/57 个 `poc.sh` 通过跨平台 shell 词法检查；57 个 raw HTTP 工件中 18 个通过方法/路径/TARGET 形状检查，39 个因 `ANY` 方法或请求形状不足进入人工复核。Windows 未安装 `sh`/`bash`，因此这里不是完整 shell 解释器语法验证。

## 误报/漏报归因

| 样本 | 金标类别 | finding 类型 | 结论 | 核心原因 |
|---|---|---|---|---|
| 001 | API 信息泄露（high） | 无 | 漏报 | API 字段暴露/权限语义不等同于通用 source→sink，缺少 API 专项提示 |
| 002 | API 信息泄露（low） | 无 | 漏报 | API 字段暴露/权限语义不等同于通用 source→sink，缺少 API 专项提示 |
| 003 | API 信息泄露（medium） | 无 | 漏报 | API 字段暴露/权限语义不等同于通用 source→sink，缺少 API 专项提示 |
| 004 | 认证绕过（high） | 无 | 漏报 | 类别专项规则或模型上下文不足 |
| 005 | 认证绕过（low） | 无 | 漏报 | 类别专项规则或模型上下文不足 |
| 006 | 认证绕过（medium） | 无 | 漏报 | 类别专项规则或模型上下文不足 |
| 007 | 越权/IDOR（high） | 无 | 漏报 | 对象授权关系需要业务主体/对象对比，LLM 未获得足够业务上下文 |
| 009 | 越权/IDOR（medium） | sql_injection | 误报/漏报 | 类型不匹配（实际：sql_injection）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 010 | 暴力破解（high） | sql_injection, xss | 误报/漏报 | 类型不匹配（实际：sql_injection, xss）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 011 | 暴力破解（low） | sql_injection | 误报/漏报 | 类型不匹配（实际：sql_injection）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 012 | 暴力破解（medium） | sql_injection | 误报/漏报 | 类型不匹配（实际：sql_injection）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 013 | 验证码绕过（high） | auth_bypass, sql_injection | 误报/漏报 | 类型不匹配（实际：auth_bypass, sql_injection）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 014 | 验证码绕过（low） | sql_injection | 误报/漏报 | 类型不匹配（实际：sql_injection）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 015 | 验证码绕过（medium） | auth_bypass, sql_injection | 误报/漏报 | 类型不匹配（实际：auth_bypass, sql_injection）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 016 | 弱加密（high） | 无 | 漏报 | 类别专项规则或模型上下文不足 |
| 017 | 弱加密（low） | 无 | 漏报 | 类别专项规则或模型上下文不足 |
| 018 | 弱加密（medium） | auth_bypass | 误报/漏报 | 类型不匹配（实际：auth_bypass）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 019 | CSP 配置缺陷（high） | path_traversal | 误报/漏报 | 类型不匹配（实际：path_traversal）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 020 | CSP 配置缺陷（low） | path_traversal, xss | 误报/漏报 | 类型不匹配（实际：path_traversal, xss）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 021 | CSP 配置缺陷（medium） | path_traversal | 误报/漏报 | 类型不匹配（实际：path_traversal）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 022 | CSRF（high） | path_traversal, sql_injection | 误报/漏报 | 类型不匹配（实际：path_traversal, sql_injection）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 023 | CSRF（low） | sql_injection | 误报/漏报 | 类型不匹配（实际：sql_injection）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 024 | CSRF（medium） | business_logic, sql_injection | 误报/漏报 | 类型不匹配（实际：business_logic, sql_injection）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 029 | 路径穿越/LFI（low） | 无 | 漏报 | include/路径规范化链未被当前规则稳定识别 |
| 030 | 路径穿越/LFI（medium） | 无 | 漏报 | include/路径规范化链未被当前规则稳定识别 |
| 031 | 客户端 JavaScript 校验绕过（high） | 无 | 漏报 | 客户端校验绕过需要浏览器执行语义，静态模型未形成专类候选 |
| 032 | 客户端 JavaScript 校验绕过（low） | 无 | 漏报 | 客户端校验绕过需要浏览器执行语义，静态模型未形成专类候选 |
| 033 | 客户端 JavaScript 校验绕过（medium） | 无 | 漏报 | 客户端校验绕过需要浏览器执行语义，静态模型未形成专类候选 |
| 034 | 开放重定向（high） | 无 | 漏报 | 重定向响应与可控 URL 的端点关系未被规则闭合 |
| 035 | 开放重定向（low） | 无 | 漏报 | 重定向响应与可控 URL 的端点关系未被规则闭合 |
| 036 | 开放重定向（medium） | 无 | 漏报 | 重定向响应与可控 URL 的端点关系未被规则闭合 |
| 046 | 弱 ID/可预测会话标识（high） | 无 | 漏报 | 可预测 ID 需要跨请求比较，单文件上下文不足 |
| 047 | 弱 ID/可预测会话标识（low） | 无 | 漏报 | 可预测 ID 需要跨请求比较，单文件上下文不足 |
| 048 | 弱 ID/可预测会话标识（medium） | 无 | 漏报 | 可预测 ID 需要跨请求比较，单文件上下文不足 |
| 049 | DOM 型 XSS（high） | 无 | 漏报 | 客户端脚本未进入有效 source→sink 审计路径，缺少 JS 专项核查 |
| 050 | DOM 型 XSS（low） | 无 | 漏报 | 客户端脚本未进入有效 source→sink 审计路径，缺少 JS 专项核查 |
| 051 | DOM 型 XSS（medium） | 无 | 漏报 | 客户端脚本未进入有效 source→sink 审计路径，缺少 JS 专项核查 |
| 053 | 反射型 XSS（low） | 无 | 漏报 | 输出上下文与反射路径未被规则覆盖，LLM 上下文截断或注意力不足 |
| 054 | 反射型 XSS（medium） | 无 | 漏报 | 输出上下文与反射路径未被规则覆盖，LLM 上下文截断或注意力不足 |
| 055 | 存储型 XSS（high） | sql_injection | 误报/漏报 | 类型不匹配（实际：sql_injection）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 056 | 存储型 XSS（low） | sql_injection | 误报/漏报 | 类型不匹配（实际：sql_injection）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 057 | 存储型 XSS（medium） | sql_injection | 误报/漏报 | 类型不匹配（实际：sql_injection）；通用模式偏置/Prompt 未强制按金标根因分类 |
| 058 | 二次注入（low） | auth_bypass, sql_injection | 部分命中（未标为二次注入） | 类型不匹配（实际：auth_bypass, sql_injection）；通用模式偏置/Prompt 未强制按金标根因分类 |

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
ver2 启用确定性 source→sink 候选并与 LLM 融合，增加 POC 静态契约校验，保留失败原因；这些改动改善可定位性和可审计性，但仍不能替代隔离环境中的动态验证。
