# 落日二号乙-ver3 暴风星云裂全量 URL 路径实验

- 输入模式：`url`（目标为 HTTP URL 路径，不使用 ZIP 输入）
- 目标基址：`http://127.0.0.1:18081`
- URL 路径数：65（其中 001–057 与 058_01–058_08）
- 完成：65；失败：0
- 动态候选：9；POC 合同错误：0

## 发现

| 路径 | 类型 | 严重度 | 证据 | verdict |
|---|---|---|---|---|
| `025.php` | `command_injection` | critical | `SUNSET_CMD_MARKER` | candidate |
| `026.php` | `command_injection` | critical | `SUNSET_CMD_MARKER` | candidate |
| `027.php` | `command_injection` | critical | `SUNSET_CMD_MARKER` | candidate |
| `028.php` | `path_traversal` | high | `/tmp/sunset_probe` | candidate |
| `029.php` | `path_traversal` | high | `/tmp/sunset_probe` | candidate |
| `030.php` | `path_traversal` | high | `/tmp/sunset_probe` | candidate |
| `052.php` | `xss` | high | `<script>alert(1)</script>` | candidate |
| `053.php` | `xss` | high | `<script>alert(1)</script>` | candidate |
| `054.php` | `xss` | high | `<script>alert(1)</script>` | candidate |

## 覆盖与边界

- 所有 65 个 PHP URL 路径均生成了独立 `report.json`，且 `run.input_mode=url` 与 `run.target_url` 均通过校验。
- 本地 AWVS-compatible 探针只对 cmdi、pathtraver、sqli、xss 等可由 HTTP 响应观察的类别发起探测；其余路径仍执行 URL 管线并记录零候选。
- 058 的 8 个子路径按独立 URL 覆盖；当前本地适配器没有为 SQLi-Labs 子路径提供上游路由，因此结果为零候选，不将 DVWA 回退路径当作 058 证据。
- POC 仅写入报告，未执行；动态候选仍标记为 `candidate`/`external_only`，不是最终人工确认。
