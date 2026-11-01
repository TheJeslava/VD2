# 落日验证报告

- 生成时间：2026-10-31T13:55:23.746992+00:00
- 模式：`zip`
- 目标基址：`http://127.0.0.1:18081`
- 结果目录：`results\暴风星云裂_ver5_joint_zip_awvs_llmfinding_20261031\014`

## 汇总

- 总数：5
- verified：0
- rejected：4
- inconclusive：1
- unsupported：0
- error：0

| finding | 类型 | 结论 | 置信度 | baseline | attack | 原因 |
|---|---|---|---|---|---|---|
| `GEN-74a307a2a91c` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-b52a2b477f7b` | `csrf` | **rejected** | 0.5 | 404 | 404 | no meaningful differential between baseline and attack |
| `SEM-161a1ab1f6bd` | `captcha_bypass` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-75da972f9cc2` | `weak_hash` | **rejected** | 0.5 | 404 | 404 | no meaningful differential between baseline and attack |
| `SEM-16d21f2078ab` | `csrf` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |

## 安全边界

- 仅执行解析出的 HTTP 请求，不执行 POC shell 脚本。
- 仅允许 localhost/127.0.0.1/::1 与显式 allowlist 主机。
- 验证结果中的 `executed=true` 仅表示本验证器执行了请求。