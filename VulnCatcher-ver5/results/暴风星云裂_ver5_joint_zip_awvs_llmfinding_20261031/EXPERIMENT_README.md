# 暴风星云裂 ver5 ZIP + URL/AWVS 联合实验（2026-10-31）

## 配置与范围

- 工具链：落日二号乙 ver5 ZIP 线路，启用 LLM finding；使用 URL 探针采集动态证据，并将 AWVS-compatible 探针报告回灌联合分析。
- 数据：暴风星云裂 001–058，共 58 个样本。
- 并发：4 路。
- URL 探针：58/58 个目标完成，产生 25 条动态 finding。
- ZIP 联合任务：58/58 完成，0 失败。
- 最终结果：125 findings、125 个 POC 工件；来源统计为 rule 83、LLM finding 33、AWVS 9。

## 评估与验证

- 金标类别严格匹配：50 个样本命中、7 个类别误报、8 个类别漏报；finding 存在性命中 57/58。
- POC 静态检查：103 个与 finding 一致、7 个不一致、15 个不可执行。
- 落日验证：对 50 个金标预测正确的样本中可验证的 POC 执行验证，共 90 个 POC；verified 24、rejected 42、inconclusive 24。
- 与金标类别一致的 verified POC：22 个。

落日验证/results/zip/暴风星云裂_ver5_joint_20261031/ 保存本次验证批次报告。逐样本验证文件和最终汇总也保留在 ZIP 联合结果目录中。

## 目录

- 暴风星云裂_ver5_joint_zip_awvs_llmfinding_20261031/：58 个样本的联合扫描、最终报告、POC、验证记录和运行日志。
- 暴风星云裂_ver5_joint_url_20261031/：URL 探针逐样本结果及汇总。
- 暴风星云裂_ver5_joint_awvs_reports_20261031/：回灌的 58 份 AWVS-compatible 报告。

## 验证限制

URL 探针运行在本机隔离的 127.0.0.1:18081 AWVS-compatible DVWA adapter 上。adapter 将样本路径映射到 DVWA 类别路由，并非原始 58 个 PHP 样本的完整部署。验证结果中的 verified 表示响应证据符合验证器标记；matching_verified 还要求漏洞类别与金标一致。POC 工件作为报告内容保存，不代表这些工件在生产目标上执行。