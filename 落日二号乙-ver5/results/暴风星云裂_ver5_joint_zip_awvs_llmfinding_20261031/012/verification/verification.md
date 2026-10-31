# 落日验证报告

- 生成时间：2026-10-31T13:55:23.314930+00:00
- 模式：`zip`
- 目标基址：`http://127.0.0.1:18081`
- 结果目录：`results\暴风星云裂_ver5_joint_zip_awvs_llmfinding_20261031\012`

## 汇总

- 总数：3
- verified：0
- rejected：2
- inconclusive：1
- unsupported：0
- error：0

| finding | 类型 | 结论 | 置信度 | baseline | attack | 原因 |
|---|---|---|---|---|---|---|
| `GEN-3b547dba7a60` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `SEM-536ee862bb25` | `brute_force` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-a7383455f404` | `xss` | **rejected** | 0.6 | 200 | 200 | no unencoded script reflection observed |

## 安全边界

- 仅执行解析出的 HTTP 请求，不执行 POC shell 脚本。
- 仅允许 localhost/127.0.0.1/::1 与显式 allowlist 主机。
- 验证结果中的 `executed=true` 仅表示本验证器执行了请求。