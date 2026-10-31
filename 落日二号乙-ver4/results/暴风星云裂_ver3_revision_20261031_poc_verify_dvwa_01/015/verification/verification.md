# 落日验证报告

- 生成时间：2026-10-31T02:58:29.241260+00:00
- 模式：`zip`
- 目标基址：`http://127.0.0.1:18081`
- 结果目录：`C:\Users\liyuf\Desktop\794\落日二号乙-ver3\results\暴风星云裂_ver3_revision_20261031_poc_verify_dvwa_01\015`

## 汇总

- 总数：5
- verified：0
- rejected：4
- inconclusive：1
- unsupported：0
- error：0

| finding | 类型 | 结论 | 置信度 | baseline | attack | 原因 |
|---|---|---|---|---|---|---|
| `GEN-c00a42452f04` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-c737fb0d7fd9` | `captcha_bypass` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-2b846713ecdc` | `captcha_bypass` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-1c448a06ff3b` | `weak_hash` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-bb70b3793387` | `csrf` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |

## 安全边界

- 仅执行解析出的 HTTP 请求，不执行 POC shell 脚本。
- 仅允许 localhost/127.0.0.1/::1 与显式 allowlist 主机。
- 验证结果中的 `executed=true` 仅表示本验证器执行了请求。