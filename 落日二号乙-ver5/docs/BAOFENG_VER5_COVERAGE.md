# 暴风星云裂 ver5 覆盖矩阵

| 金标编号 | URL/AWVS 类别 | 内部类型 | 动态策略 |
|---|---|---|---|
| 001–003 | API 信息泄露 | `api_info_disclosure` | JSON/敏感字段差异 |
| 004–006 | 认证绕过 | `auth_bypass` | 权限响应差异 |
| 007–009 | 越权 / IDOR | `idor` | 对象 ID 响应差异 |
| 010–012 | 暴力破解 | `brute_force` | 失败次数后的限速/锁定信号 |
| 013–015 | 验证码绕过 | `captcha_bypass` | 无效验证码后的成功状态 |
| 016–018 | 弱加密 | `weak_crypto` | 清单静态证据，需 ZIP/人工复核 |
| 019–021 | CSP 配置缺陷 | `csp` | 响应头策略检查 |
| 022–024 | CSRF | `csrf` | POST 表单和 token 检查 |
| 025–027 | 命令注入 | `command_injection` | 命令输出/标记差异 |
| 028–030 | 路径穿越 / LFI | `path_traversal` | 文件内容/路径标记差异 |
| 031–033 | 客户端校验绕过 | `client_side_validation` | HTML/JS 校验存在性 |
| 034–036 | 开放重定向 | `open_redirect` | `Location` 外部地址 |
| 037–039 | 盲 SQL 注入 | `blind_sql_injection` | 布尔/时间/响应长度差异 |
| 040–042 | SQL 注入 | `sql_injection` | SQL 错误/行集差异 |
| 043–045 | 文件上传 | `file_upload` | 上传响应信号 |
| 046–048 | 弱 ID | `weak_id` | 可预测 Cookie |
| 049–051 | DOM 型 XSS | `xss` | DOM source/sink |
| 052–054 | 反射型 XSS | `xss` | 未编码 payload 反射 |
| 055–057 | 存储型 XSS | `xss` | 写入/回显信号；需跨请求复核 |
| 058 | 二次注入 | `second_order_injection` | 单请求不确认；需跨请求动态流程或外部报告 |

清单中的样本编号、类别、CWE 和参数只用于构造测试目标与选择探针通道，不会单独生成 finding。没有 HTTP 证据的目标保持无 finding。

生成清单：`python tools/generate_baofeng_manifest.py`。完整 URL 批处理：`powershell -File ..\\run_baofeng_ver5.ps1`。
