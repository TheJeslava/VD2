# 落日验证报告

- 生成时间：2026-10-31T13:55:27.888990+00:00
- 模式：`zip`
- 目标基址：`http://127.0.0.1:18081`
- 结果目录：`results\暴风星云裂_ver5_joint_zip_awvs_llmfinding_20261031\051`

## 汇总

- 总数：2
- verified：0
- rejected：2
- inconclusive：0
- unsupported：0
- error：0

| finding | 类型 | 结论 | 置信度 | baseline | attack | 原因 |
|---|---|---|---|---|---|---|
| `AWVS-3b651ba72b42` | `xss` | **rejected** | 0.6 | 200 | 200 | no unencoded script reflection observed |
| `GEN-6e4cfba5fa5e` | `open_redirect` | **rejected** | 0.6 | 200 | 200 | no redirect status and Location header observed |

## 安全边界

- 仅执行解析出的 HTTP 请求，不执行 POC shell 脚本。
- 仅允许 localhost/127.0.0.1/::1 与显式 allowlist 主机。
- 验证结果中的 `executed=true` 仅表示本验证器执行了请求。