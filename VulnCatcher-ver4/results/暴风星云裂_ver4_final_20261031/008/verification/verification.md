# 落日验证报告

- 生成时间：2026-10-31T09:47:35.064315+00:00
- 模式：`zip`
- 目标基址：`http://127.0.0.1:18081`
- 结果目录：`C:\Users\liyuf\Desktop\794\落日二号乙-ver4\results\暴风星云裂_ver4_final_20261031\008`

## 汇总

- 总数：6
- verified：1
- rejected：0
- inconclusive：5
- unsupported：0
- error：0

| finding | 类型 | 结论 | 置信度 | baseline | attack | 原因 |
|---|---|---|---|---|---|---|
| `GEN-f0aa8e8c7f6b` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `GEN-efda4d219748` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `GEN-31888d7d7e9c` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-be8d58eeb7fa` | `idor` | **verified** | 0.75 | 200 | 200 | object profile returned under attacker-controlled identifier; compare with same-user baseline |
| `LLM-f5edf35e32f8` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `SEM-e3f1dc6ea55d` | `weak_id` | **inconclusive** | 0.45 | 200 | 200 | no numeric session cookie observed; multi-request comparison required |

## 安全边界

- 仅执行解析出的 HTTP 请求，不执行 POC shell 脚本。
- 仅允许 localhost/127.0.0.1/::1 与显式 allowlist 主机。
- 验证结果中的 `executed=true` 仅表示本验证器执行了请求。