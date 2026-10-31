# 落日验证报告

- 生成时间：2026-10-31T09:17:38.413018+00:00
- 模式：`zip`
- 目标基址：`http://127.0.0.1:18081`
- 结果目录：`C:\Users\liyuf\Desktop\794\落日二号乙-ver4\results\暴风星云裂_ver4_20261031\058`

## 汇总

- 总数：9
- verified：0
- rejected：3
- inconclusive：6
- unsupported：0
- error：0

| finding | 类型 | 结论 | 置信度 | baseline | attack | 原因 |
|---|---|---|---|---|---|---|
| `GEN-b07a62da291f` | `sql_injection` | **inconclusive** | 0.45 | 404 | 404 | no SQL error or row-set change observed (possible blind injection) |
| `GEN-7923d3edceea` | `sql_injection` | **inconclusive** | 0.45 | 404 | 404 | no SQL error or row-set change observed (possible blind injection) |
| `GEN-2e336c5d86ca` | `sql_injection` | **inconclusive** | 0.45 | 404 | 404 | no SQL error or row-set change observed (possible blind injection) |
| `GEN-14a19460b45a` | `sql_injection` | **inconclusive** | 0.45 | 404 | 404 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-294d609e1b45` | `auth_bypass` | **rejected** | 0.5 | 404 | 404 | no meaningful differential between baseline and attack |
| `SEM-381e6544791c` | `weak_id` | **inconclusive** | 0.45 | 404 | 404 | no numeric session cookie observed; multi-request comparison required |
| `SEM-84e9d7c625f8` | `weak_id` | **inconclusive** | 0.45 | 404 | 404 | no numeric session cookie observed; multi-request comparison required |
| `LLM-a8e9805999ee` | `xss` | **rejected** | 0.6 | 404 | 404 | no unencoded script reflection observed |
| `SEM-e3f6e1c06f4d` | `csrf` | **rejected** | 0.5 | 404 | 404 | no meaningful differential between baseline and attack |

## 安全边界

- 仅执行解析出的 HTTP 请求，不执行 POC shell 脚本。
- 仅允许 localhost/127.0.0.1/::1 与显式 allowlist 主机。
- 验证结果中的 `executed=true` 仅表示本验证器执行了请求。