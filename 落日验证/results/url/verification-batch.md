# 落日验证报告

- 生成时间：2026-10-29T17:42:22.123853+00:00
- 模式：`url`
- 目标基址：`(POC 自带)`
- 结果目录：``

## 汇总

- 总数：20
- verified：20
- rejected：0
- inconclusive：0
- unsupported：0
- error：0

| finding | 类型 | 结论 | 置信度 | baseline | attack | 原因 |
|---|---|---|---|---|---|---|
| `URL-36b81fd0872c` | `path_traversal` | **verified** | 0.85 | 200 | 200 | traversal marker in attack response: '../' |
| `URL-c19a3fae2337` | `path_traversal` | **verified** | 0.85 | 200 | 200 | traversal marker in attack response: '../' |
| `URL-f031d6fa4f9e` | `command_injection` | **verified** | 0.9 | 200 | 200 | command output marker in attack response |
| `URL-2a860947b9a9` | `command_injection` | **verified** | 0.9 | 200 | 200 | command output marker in attack response |
| `URL-3121ace687b5` | `sql_injection` | **verified** | 0.85 | 500 | 500 | SQL error marker in attack response: 'unexpected token' |
| `URL-803567449d27` | `path_traversal` | **verified** | 0.85 | 200 | 200 | traversal marker in attack response: '../' |
| `URL-da29ee4883e0` | `xss` | **verified** | 0.9 | 200 | 200 | unencoded script payload reflected in attack response |
| `URL-d488592e9085` | `ldap_injection` | **verified** | 0.8 | 200 | 200 | attack response exposes more LDAP records than baseline |
| `URL-b018851ee8fc` | `xss` | **verified** | 0.9 | 200 | 200 | unencoded script payload reflected in attack response |
| `URL-8f1bc8512395` | `command_injection` | **verified** | 0.9 | 200 | 200 | command output marker in attack response |
| `URL-45e20fd6269d` | `sql_injection` | **verified** | 0.85 | 200 | 500 | SQL error marker in attack response: 'sqlexception' |
| `URL-61d3fbf66d19` | `ldap_injection` | **verified** | 0.8 | 200 | 200 | attack response exposes more LDAP records than baseline |
| `URL-82f42874d68c` | `xss` | **verified** | 0.9 | 200 | 200 | unencoded script payload reflected in attack response |
| `URL-9f3733726150` | `sql_injection` | **verified** | 0.75 | 200 | 200 | attack response exposes more result rows than baseline |
| `URL-d44989259b73` | `ldap_injection` | **verified** | 0.8 | 200 | 200 | attack response exposes more LDAP records than baseline |
| `URL-4eedb0bca02d` | `insecure_cookie` | **verified** | 0.9 | 200 | 200 | Set-Cookie for SomeCookie lacks the Secure flag |
| `URL-2d959dfbded8` | `insecure_cookie` | **verified** | 0.9 | 200 | 200 | Set-Cookie for SomeCookie lacks the Secure flag |
| `URL-ec06ca3833d1` | `insecure_cookie` | **verified** | 0.9 | 200 | 200 | Set-Cookie for SomeCookie lacks the Secure flag |
| `URL-59cfa4ed6fec` | `xpath_injection` | **verified** | 0.78 | 200 | 200 | XPath query returned a different record than baseline |
| `URL-080826955344` | `xpath_injection` | **verified** | 0.78 | 200 | 200 | XPath query returned a different record than baseline |

## 安全边界

- 仅执行解析出的 HTTP 请求，不执行 POC shell 脚本。
- 仅允许 localhost/127.0.0.1/::1 与显式 allowlist 主机。
- 验证结果中的 `executed=true` 仅表示本验证器执行了请求。