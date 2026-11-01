# 落日验证报告

- 生成时间：2026-10-31T13:55:27.097327+00:00
- 模式：`zip`
- 目标基址：`http://127.0.0.1:18081`
- 结果目录：`results\暴风星云裂_ver5_joint_zip_awvs_llmfinding_20261031\044`

## 汇总

- 总数：2
- verified：2
- rejected：0
- inconclusive：0
- unsupported：0
- error：0

| finding | 类型 | 结论 | 置信度 | baseline | attack | 原因 |
|---|---|---|---|---|---|---|
| `GEN-7d549df94451` | `file_upload` | **verified** | 0.85 | 200 | 200 | multipart upload accepted and upload path disclosed |
| `LLM-6ccece6535f3` | `file_upload` | **verified** | 0.85 | 200 | 200 | multipart upload accepted and upload path disclosed |

## 安全边界

- 仅执行解析出的 HTTP 请求，不执行 POC shell 脚本。
- 仅允许 localhost/127.0.0.1/::1 与显式 allowlist 主机。
- 验证结果中的 `executed=true` 仅表示本验证器执行了请求。