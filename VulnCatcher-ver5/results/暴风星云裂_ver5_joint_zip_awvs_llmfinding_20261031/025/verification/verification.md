# 落日验证报告

- 生成时间：2026-10-31T13:55:25.545294+00:00
- 模式：`zip`
- 目标基址：`http://127.0.0.1:18081`
- 结果目录：`results\暴风星云裂_ver5_joint_zip_awvs_llmfinding_20261031\025`

## 汇总

- 总数：3
- verified：2
- rejected：1
- inconclusive：0
- unsupported：0
- error：0

| finding | 类型 | 结论 | 置信度 | baseline | attack | 原因 |
|---|---|---|---|---|---|---|
| `LLM-77434b11a59f` | `command_injection` | **rejected** | 0.6 | 200 | 200 | no command output marker observed |
| `GEN-2da8a6e02c4e` | `command_injection` | **verified** | 0.9 | 200 | 200 | command output marker in attack response |
| `GEN-eff51e7cd060` | `command_injection` | **verified** | 0.9 | 200 | 200 | command output marker in attack response |

## 安全边界

- 仅执行解析出的 HTTP 请求，不执行 POC shell 脚本。
- 仅允许 localhost/127.0.0.1/::1 与显式 allowlist 主机。
- 验证结果中的 `executed=true` 仅表示本验证器执行了请求。