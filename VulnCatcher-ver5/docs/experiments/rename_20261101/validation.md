# 统一命名后的验证记录

基础提交：`b2e3fadf66ddf18e177ee7c2979c71ac54e9d813`。本次统一产品显示名为 VulnCatcher，样本集合名称为集成数据集；ver1 至 ver5 的目录保留版本区分。

目录、现行文档、提示词、CLI、生成报告和数据集默认路径均使用新名称。Python 包及命令入口 `sunset`、`sunset-two` 分发名和已有 `baofeng_*` 工具标识保持兼容；独立验证模块保留名称。

历史 `results/` 与 `docs/experiments/logic_20261101/` 按原字节保留。原始 PHP/ZIP 样本内容保持一致；Git blob 校验见 [rename_integrity.json](rename_integrity.json)。

## 验证结果

| 检查 | 结果 | 记录 |
|---|---|---|
| 最新 ver5 全套回归 | 108 项，0 失败、0 错误，4 项因原有缺失夹具跳过 | [tests.log](tests.log)、[tests_summary.json](tests_summary.json) |
| 三类业务规则静态对照 | 11/11：4 candidate、4 guarded、3 needs_context | [experiment.json](experiment.json) |
| 本地 HTTP 与业务状态对照 | 32/32 满足预期 | [experiment.md](experiment.md) |
| 主扫描管线 | 4 个专属 Finding；报告校验通过，generator 为 VulnCatcher | [pipeline_summary.json](pipeline_summary.json)、[pipeline/report.md](pipeline/report.md) |
| 五个版本 CLI 帮助与版本输出 | 10/10 成功，均显示 VulnCatcher | [cli_checks.json](cli_checks.json) |
| 最新 ver5 自检 | 5 个自检项通过 | [cli_checks.json](cli_checks.json) |
| 数据集路径 | 改名后仍可读取 014.php、015.php 并完成静态分析 | [experiment.json](experiment.json) |

实验使用 Python 3.14.3，仅访问 `127.0.0.1` 随机端口上的自带教学服务，未调用真实 LLM、AWVS 或外部目标。原始 PHP/DVWA 样本未做动态验证；主扫描流程未执行目标 POC。最初在受限沙箱内访问本地 HTTP 被阻止，随后在允许本地套接字的环境完成上述运行。

## 旧版本基线

额外检查 ver2 内置自检时，`rule_candidates_disabled` 与 `no_static_rule_finding` 两项失败。使用基础提交的 ver2 源码与提示词重跑，得到相同的两项失败，其余三项通过。该旧版断言仍要求禁用已恢复的规则引擎，与命名变更无关；本次保留历史版本行为。对照输出见 [ver2_baseline_selftest.json](ver2_baseline_selftest.json)。

## 复现

在 `VulnCatcher-ver5/` 执行：

```powershell
python -m unittest discover -s tests -v
python -m sunset selftest
python -m examples.logic_lab.run_experiment --out .\sunset-results\rename-check
```

本目录是在新目录结构下实际重跑得到的记录；历史档案中的旧名称与绝对路径代表当时环境。
