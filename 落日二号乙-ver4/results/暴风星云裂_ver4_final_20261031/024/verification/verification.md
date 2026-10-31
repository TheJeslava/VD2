# 落日验证报告

- 生成时间：2026-10-31T09:47:38.375951+00:00
- 模式：`zip`
- 目标基址：`http://127.0.0.1:18081`
- 结果目录：`C:\Users\liyuf\Desktop\794\落日二号乙-ver4\results\暴风星云裂_ver4_final_20261031\024`

## 汇总

- 总数：4
- verified：0
- rejected：3
- inconclusive：1
- unsupported：0
- error：0

| finding | 类型 | 结论 | 置信度 | baseline | attack | 原因 |
|---|---|---|---|---|---|---|
| `GEN-cf38b1a2cb95` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-3eef1cf779fd` | `csrf` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-72b85cc24676` | `brute_force` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-7bbc11033fc9` | `weak_hash` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |

## 安全边界

- 仅执行解析出的 HTTP 请求，不执行 POC shell 脚本。
- 仅允许 localhost/127.0.0.1/::1 与显式 allowlist 主机。
- 验证结果中的 `executed=true` 仅表示本验证器执行了请求。