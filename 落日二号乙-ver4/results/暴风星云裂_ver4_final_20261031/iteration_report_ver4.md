# 暴风星云裂 ver4 最终迭代报告

## 运行与评估

- 最终管线：`落日二号乙-ver4`，58 个 ZIP，4 路并发，58/58 完成，0 失败。
- LLM 设置：`--llm on --llm-finding on`；每个样本的模型调用记录在对应 `manifest.json`。
- 严格类别匹配：TP=40，FP=10，FN=18；Precision=80.00%，Recall=68.97%，F1=74.07%。
- ver3 revision 基线：TP=39，FP=11，FN=19；Precision=78.00%，Recall=67.24%，F1=72.22%。
- 数据集 58 个样本全部是正例，不能从该集合计算 TN、特异度或常规二分类 accuracy。

逐样本的 20 类别 low/medium/high 表格、误报/漏报归因和 POC 静态契约明细见 `evaluation_vs_gold_ver2.md/json`。

## 管线改动

- `sunset/poc.py`：弱 ID POC 改为同一 Cookie jar 的连续 POST；来源为 Cookie 的 weak_id 不再因缺少显式 `Cookie:` 被静态契约误判。
- `落日验证-ver4/sunset_verify/collector.py`：保留 POC 中全部攻击步骤，而不是只取第一条请求。
- `落日验证-ver4/sunset_verify/agents/executor_agent.py`：顺序执行多请求并吸收/回传 `Set-Cookie`，仅限 allowlist 本地目标。
- `落日验证-ver4/sunset_verify/judge.py`：weak_id 至少需要两次攻击响应的连续数字 Cookie 才能 `verified`；单次数字 Cookie 为 `inconclusive`。
- `落日验证-ver4/sunset_verify/reporter_agent.py`：逐条报告保存 `attack_sequence`，CSV 记录攻击步骤数。
- `tools/verify_baofeng_gold_hits.py`：按金标类别命中样本筛选并回放所有可解析 POC。

## 动态验证

- 金标类别命中样本：40 个；可回放 POC：81 条。
- 结果：`verified=25`、`rejected=35`、`inconclusive=21`、`error=0`。
- 与金标类别一致的 verified POC：23 条，覆盖样本 `008,009,019,020,021,025,026,027,043,044,045,046,047,048,052,053,054`。
- 047 实操证据：验证器顺序发送两次 POST，并在同一 Cookie jar 中观察 `dvwaSession=1`、`dvwaSession=2`；判定理由为连续数字会话标识，而非单次 Cookie 推断。

动态明细：`verification_vs_gold.md/json` 和 `暴风星云裂_ver4_final_gold_verification_20261031/verification-batch.json`。

## 验证边界

落日验证只解析并执行 HTTP 请求，不执行 POC shell；目标为本机 `127.0.0.1:18081` 的隔离 DVWA 适配层。适配层把样本编号映射到 DVWA 路由，因此动态 verified 是隔离靶场响应证据，不等同于原始 PHP 部署的完整复现。弱加密、静态配置和没有可解析 HTTP 请求的 POC 仍由静态报告记录。
