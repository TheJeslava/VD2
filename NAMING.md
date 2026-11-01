# 命名与兼容说明

VulnCatcher 是项目产品名，集成数据集是样本集合，VulnCatcher-Verify 是独立 POC 验证模块。五个版本分别位于 `VulnCatcher-ver1/` 至 `VulnCatcher-ver5/`。

## 运行入口

- 主程序：安装后使用 `vulncatcher`；源码运行继续使用 `python -m sunset`，原 `sunset` 命令保留兼容。
- 验证程序：位于 `VulnCatcher-Verify/`；安装后使用 `vulncatcher-verify`，源码运行使用 `python -m sunset_verify`，原 `sunset-verify` 命令保留兼容。
- 主程序默认输出目录为 `vulncatcher-results/`，也可通过 `--out` 指定目录。已有输出仍可按原路径读取；新旧输出目录都已加入 Git 忽略规则。
- Python 内部包 `sunset`、`sunset_verify` 和分发名称保持兼容；数据格式中的既有字段名称保持稳定。

## 数据集工具

现行文档使用下表的新入口。旧 Python 脚本是兼容包装，调用同一份实现，原有可导入函数也继续可用。各版本保留该版本原有的工具集合。

| 新入口 | 兼容入口 |
|---|---|
| `dataset_evaluate.py` | `evaluate_baofeng.py` |
| `dataset_generate_manifest.py` | `generate_baofeng_manifest.py` |
| `dataset_run_hybrid.py` | `run_baofeng_hybrid.py` |
| `dataset_run_url.py` | `run_baofeng_url.py` |
| `dataset_summarize_url.py` | `summarize_baofeng_url.py` |
| `dataset_summarize_verification.py` | `summarize_baofeng_verification.py` |
| `dataset_verify_gold_hits.py` | `verify_baofeng_gold_hits.py` |
| `dataset_dvwa_adapter.py` | `baofeng_dvwa_adapter.py` |

ver5 的清单生成器默认写入 `runtime/dataset-targets.json`，原 `runtime/baofeng-targets.json` 保留为兼容数据文件。覆盖矩阵位于 `VulnCatcher-ver5/docs/DATASET_VER5_COVERAGE.md`，原文档路径保留跳转说明。

历史实验档案保留运行时的原始名称、路径和校验值；新运行按本页现行路径执行。

完整回归、旧新工具等价性、默认输出和本地实验结果见 [验证记录](VulnCatcher-ver5/docs/experiments/naming_compat_20261101/validation.md)。
