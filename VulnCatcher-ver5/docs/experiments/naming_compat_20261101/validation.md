# 命名与兼容迁移验证

基础提交：`51714fe0afb1c98fedaf4a8ba79d6dda4e3b83b5`。本次将 ver1 目录明确为 `VulnCatcher-ver1/`，验证模块改为 `VulnCatcher-Verify/`，主程序默认输出改为 `vulncatcher-results/`，数据集工具采用 `dataset_*` 入口。

## 改动与兼容

- 五个版本新增 `vulncatcher` 控制台入口，验证器新增 `vulncatcher-verify`。旧 `sunset`、`sunset-verify` 命令和 Python 包名保留兼容。
- 19 个数据集工具迁移到新名称，旧入口转发到同一实现，兼容普通导入、`tools.*` 导入、按路径加载和既有函数 API。
- ver4/ver5 的数据集验证工具改为从仓库内 `VulnCatcher-Verify` 加载验证器，修复原先指向不存在目录的问题。
- manifest 新默认名称为 `runtime/dataset-targets.json`；原 JSON 文件及数据格式字段保留兼容。覆盖矩阵旧文档路径提供新文档链接。
- 历史实验和原始数据样本保持原字节；完整性检查见 [rename_integrity.json](rename_integrity.json)。

## 执行结果

| 检查 | 结果 | 记录 |
|---|---|---|
| ver5 全套回归（含新增 4 项兼容回归） | 112 项，0 失败、0 错误，4 项因原有缺失样本跳过 | [tests.log](tests.log)、[tests_summary.json](tests_summary.json) |
| 验证器现有回归 | 6/6 通过 | [verification_tests.log](verification_tests.log) |
| 五个版本 CLI 帮助/版本、最新自检、验证器帮助/版本 | 13/13 通过；控制台新旧别名指向相同函数 | [cli_checks.json](cli_checks.json) |
| 数据集新旧工具帮助与验证器加载路径 | 10/10 通过，适配器帮助不会启动服务 | [tool_cli_checks.json](tool_cli_checks.json) |
| manifest 新默认路径和旧入口等价性 | 新默认文件成功生成，58 个目标；旧新内容一致 | [manifest_check.json](manifest_check.json) |
| 业务规则静态对照 | 11/11 满足预期 | [experiment.json](experiment.json) |
| 本地 HTTP 与状态对照 | 32/32 满足预期 | [experiment.md](experiment.md) |
| 实际 ZIP 主流程默认输出 | 写入 `vulncatcher-results/<run-id>`；4 candidate、4 guarded、3 needs_context，4 个专属 Finding，报告 schema 通过 | [pipeline_summary.json](pipeline_summary.json) |

测试使用 Python 3.14.3。真实 HTTP 仅限本机随机端口的自带教学服务；无真实模型调用、外部扫描服务或外部目标访问。原始 PHP/DVWA 样本仅做静态分析，目标 POC 未在主扫描流程执行。

验证器测试临时目录最初放在 `.work` 中，被批量结果发现逻辑按设计排除；移到已忽略的 `vulncatcher-results` 临时目录后，6 项测试全部通过。该调整只涉及测试运行环境。

旧版 ver2 的既有自检断言问题已在此前 [基线记录](../rename_20261101/ver2_baseline_selftest.json) 中核对，本次未修改其检测行为。

## 复现

在 `VulnCatcher-ver5/` 运行 `python -m unittest discover -s tests -v`、`python -m sunset selftest`；在 `VulnCatcher-Verify/` 运行 `python -m unittest discover -s tests -v`。本地对照实验命令为：

```powershell
python -m examples.logic_lab.run_experiment --out .\vulncatcher-results\naming-compat-check
```

验证器测试请使用不含 `.work` 或 `verification` 路径分量的临时目录。新旧工具与命令映射见仓库根目录 [NAMING.md](../../../../NAMING.md)。
