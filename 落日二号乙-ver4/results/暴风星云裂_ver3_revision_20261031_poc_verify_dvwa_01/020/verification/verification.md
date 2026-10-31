# 落日验证报告

- 生成时间：2026-10-31T02:58:29.361108+00:00
- 模式：`zip`
- 目标基址：`http://127.0.0.1:18081`
- 结果目录：`C:\Users\liyuf\Desktop\794\落日二号乙-ver3\results\暴风星云裂_ver3_revision_20261031_poc_verify_dvwa_01\020`

## 汇总

- 总数：4
- verified：1
- rejected：3
- inconclusive：0
- unsupported：0
- error：0

| finding | 类型 | 结论 | 置信度 | baseline | attack | 原因 |
|---|---|---|---|---|---|---|
| `GEN-8f1d6361cb1e` | `path_traversal` | **rejected** | 0.6 | 200 | 200 | no traversal marker or path reflection observed |
| `SEM-cc52c467496c` | `client_side_validation` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-370901c0cb4c` | `xss` | **verified** | 0.9 | 200 | 200 | unencoded script payload reflected in attack response |
| `SEM-582e93de1b73` | `csp` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |

## 安全边界

- 仅执行解析出的 HTTP 请求，不执行 POC shell 脚本。
- 仅允许 localhost/127.0.0.1/::1 与显式 allowlist 主机。
- 验证结果中的 `executed=true` 仅表示本验证器执行了请求。