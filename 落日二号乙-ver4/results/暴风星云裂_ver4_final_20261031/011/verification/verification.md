# 落日验证报告

- 生成时间：2026-10-31T09:47:35.637879+00:00
- 模式：`zip`
- 目标基址：`http://127.0.0.1:18081`
- 结果目录：`C:\Users\liyuf\Desktop\794\落日二号乙-ver4\results\暴风星云裂_ver4_final_20261031\011`

## 汇总

- 总数：3
- verified：0
- rejected：2
- inconclusive：1
- unsupported：0
- error：0

| finding | 类型 | 结论 | 置信度 | baseline | attack | 原因 |
|---|---|---|---|---|---|---|
| `LLM-c969ca7950b6` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `SEM-bb3630458a80` | `brute_force` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-996252269452` | `xss` | **rejected** | 0.6 | 200 | 200 | no unencoded script reflection observed |

## 安全边界

- 仅执行解析出的 HTTP 请求，不执行 POC shell 脚本。
- 仅允许 localhost/127.0.0.1/::1 与显式 allowlist 主机。
- 验证结果中的 `executed=true` 仅表示本验证器执行了请求。