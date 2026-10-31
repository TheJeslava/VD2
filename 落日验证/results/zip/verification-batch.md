# 落日验证报告

- 生成时间：2026-10-29T17:47:09.989939+00:00
- 模式：`zip`
- 目标基址：`http://localhost:8080/benchmark`
- 结果目录：``

## 汇总

- 总数：29
- verified：11
- rejected：15
- inconclusive：3
- unsupported：0
- error：0

| finding | 类型 | 结论 | 置信度 | baseline | attack | 原因 |
|---|---|---|---|---|---|---|
| `JAVA-e7775db9db5a` | `path_traversal` | **verified** | 0.85 | 200 | 200 | traversal marker in attack response: '../' |
| `JAVA-c1df6a92dc18` | `path_traversal` | **verified** | 0.85 | 200 | 200 | traversal marker in attack response: '../' |
| `JAVA-3b56dd117b51` | `sql_injection` | **inconclusive** | 0.45 | 500 | 500 | no SQL error or row-set change observed (possible blind injection) |
| `JAVA-56e06d7609fe` | `command_injection` | **verified** | 0.9 | 200 | 200 | command output marker in attack response |
| `JAVA-dc237a61456a` | `xss` | **verified** | 0.9 | 200 | 200 | unencoded script payload reflected in attack response |
| `JAVA-57ffb76561cb` | `xss` | **verified** | 0.9 | 200 | 200 | unencoded script payload reflected in attack response |
| `JAVA-fbf08bce540e` | `command_injection` | **verified** | 0.9 | 200 | 200 | command output marker in attack response |
| `JAVA-c568522eb7cb` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `JAVA-f7897f21c458` | `ldap_injection` | **verified** | 0.8 | 200 | 200 | attack response exposes more LDAP records than baseline |
| `JAVA-eae66bbd02f8` | `ldap_injection` | **verified** | 0.8 | 200 | 200 | attack response exposes more LDAP records than baseline |
| `JAVA-f0206e516b72` | `sql_injection` | **verified** | 0.75 | 200 | 200 | attack response exposes more result rows than baseline |
| `JAVA-43eb26b53ae1` | `xss` | **rejected** | 0.6 | 200 | 200 | no unencoded script reflection observed |
| `JAVA-82dfb2f7211f` | `ldap_injection` | **verified** | 0.8 | 200 | 200 | attack response exposes more LDAP records than baseline |
| `JAVA-d337b23d0d5b` | `path_traversal` | **rejected** | 0.6 | 200 | 200 | no traversal marker or path reflection observed |
| `JAVA-056f7524d540` | `path_traversal` | **rejected** | 0.6 | 200 | 200 | no traversal marker or path reflection observed |
| `JAVA-e35f311de0cb` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `JAVA-ce8502671635` | `xss` | **rejected** | 0.6 | 200 | 200 | no unencoded script reflection observed |
| `JAVA-0d2101b4a2f7` | `xss` | **rejected** | 0.6 | 200 | 200 | no unencoded script reflection observed |
| `JAVA-5f4cc5cbf63f` | `xpath_injection` | **rejected** | 0.55 | 200 | 200 | no LDAP/XPath-specific differential observed |
| `JAVA-934fbbd2ca6b` | `xss` | **rejected** | 0.6 | 200 | 200 | no unencoded script reflection observed |
| `JAVA-62da36ff1d3a` | `xss` | **rejected** | 0.6 | 200 | 200 | no unencoded script reflection observed |
| `JAVA-473b374786d4` | `ldap_injection` | **rejected** | 0.55 | 200 | 200 | no LDAP/XPath-specific differential observed |
| `JAVA-695b2fcdb6a1` | `xss` | **rejected** | 0.6 | 200 | 200 | no unencoded script reflection observed |
| `JAVA-3c967fa0f078` | `xpath_injection` | **rejected** | 0.55 | 200 | 200 | no LDAP/XPath-specific differential observed |
| `JAVA-cdda1b63cf69` | `xss` | **rejected** | 0.6 | 200 | 200 | no unencoded script reflection observed |
| `JAVA-0c5577df2b6d` | `xpath_injection` | **verified** | 0.78 | 200 | 200 | XPath query returned a different record than baseline |
| `JAVA-d0b96ffa9387` | `xss` | **rejected** | 0.6 | 200 | 200 | no unencoded script reflection observed |
| `JAVA-5aa5654d822c` | `xpath_injection` | **rejected** | 0.55 | 200 | 200 | no LDAP/XPath-specific differential observed |
| `JAVA-17a0491816f2` | `xss` | **rejected** | 0.6 | 200 | 200 | no unencoded script reflection observed |

## 安全边界

- 仅执行解析出的 HTTP 请求，不执行 POC shell 脚本。
- 仅允许 localhost/127.0.0.1/::1 与显式 allowlist 主机。
- 验证结果中的 `executed=true` 仅表示本验证器执行了请求。