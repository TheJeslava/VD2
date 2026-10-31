# 落日验证报告

- 生成时间：2026-10-31T02:58:29.822327+00:00
- 模式：`zip`
- 目标基址：`http://127.0.0.1:18081`
- 结果目录：`C:\Users\liyuf\Desktop\794\落日二号乙-ver3\results\暴风星云裂_ver3_revision_20261031_poc_verify_dvwa_01\052`

## 汇总

- 总数：1
- verified：1
- rejected：0
- inconclusive：0
- unsupported：0
- error：0

| finding | 类型 | 结论 | 置信度 | baseline | attack | 原因 |
|---|---|---|---|---|---|---|
| `LLM-4be6b4e0336a` | `xss` | **verified** | 0.9 | 200 | 200 | unencoded script payload reflected in attack response |

## 安全边界

- 仅执行解析出的 HTTP 请求，不执行 POC shell 脚本。
- 仅允许 localhost/127.0.0.1/::1 与显式 allowlist 主机。
- 验证结果中的 `executed=true` 仅表示本验证器执行了请求。