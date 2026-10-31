# VD2：落日二号乙与暴风星云裂

本仓库保存落日二号乙（Sunset Two Beta）的五个版本、暴风星云裂数据集，以及用于本地复现和回归测试的运行时文件。

## 内容

```text
.
├── 暴风星云裂/          # 原始 001–058 样本、压缩包和编号说明
├── 落日二号-乙/          # ver1
├── 落日二号乙-ver2/      # ver2
├── 落日二号乙-ver3/      # ver3
├── 落日二号乙-ver4/      # ver4
└── 落日二号乙-ver5/      # ver5，包含最新 URL/AWVS 管线
```

每个版本目录包含源码、提示词、运行时 fixture、测试、文档和历史实验结果。版本之间保留了演进过程，便于复现实验和比较行为。

## 暴风星云裂数据集

`暴风星云裂/` 包含 58 个样本（001–058），覆盖 20 类 Web 漏洞及对应的 PHP/ZIP 样本。`编号对应表.md` 和清洗规则文件说明样本编号、类别和预处理约定。

## 快速开始

要求 Python 3.10 或更高版本。项目主体仅使用 Python 标准库；如果某个版本目录提供了 `requirements.txt`，可按该版本说明安装依赖。

```powershell
cd 落日二号乙-ver5

# 运行自检
python -m sunset selftest

# 运行回归测试
python -m unittest discover -s tests -v
```

## ver5 URL 管线

ver5 支持三种 AWVS 候选来源：真实 AWVS API、AWVS 导出报告，以及本地 AWVS-compatible 探针。完整的 58 个目标清单位于：

```text
落日二号乙-ver5/runtime/baofeng-targets.json
```

本地隔离靶场的复现实验可使用仓库外的运行环境，并通过以下脚本启动 URL 管线：

```powershell
cd C:\path\to\VD2
powershell -File .\run_baofeng_ver5.ps1
```

也可以直接调用工具：

```powershell
cd 落日二号乙-ver5
python tools/generate_baofeng_manifest.py --base-url http://127.0.0.1:18081
python tools/run_baofeng_url.py `
  --project . `
  --base-url http://127.0.0.1:18081 `
  --out .\results\baofeng-url
```

URL 管线只把实时 HTTP 响应、AWVS 报告或本地探针返回的动态证据写入 finding。manifest 中的样本编号、类别、CWE、参数和请求方法是测试目标元数据，不会单独生成漏洞结论。`tools/baofeng_dvwa_adapter.py` 只负责本地样本路径到隔离 DVWA 路由的传输映射，不承担检测结论。

## ZIP 管线

ZIP 模式对样本源码进行安全展开、攻击面索引和漏洞候选分析，并生成报告与被动 POC 文本：

```powershell
cd 落日二号乙-ver5
python -m sunset scan C:\path\to\sample.zip --mode zip --llm off -o .\results\sample
```

POC 默认使用 `TARGET` 占位符，只写入工件，不在管线内自动执行。使用前应确认目标、靶场和网络范围均已获得授权。

## 报告输出

实验输出通常包括：

```text
report.md              # 中文摘要
report.json            # 结构化报告
findings.csv           # 表格导出
report.sarif           # SARIF 2.1.0
coverage.json          # 覆盖统计
awvs/                  # AWVS 目标和关联信息
poc/                   # 被动 POC 文本工件
```

历史结果保留在相应版本的 `results/` 目录中，用于复盘和版本对比；重新运行时可指定新的输出目录。

## 安全与配置

本仓库只用于已授权的安全测试、靶场实验和漏洞研究。不要把仓库中的配置用于未授权目标。运行真实 AWVS 或 LLM 服务时，应在本地配置凭据，并根据服务提供方的权限和配额进行管理。

更多设计细节请参阅各版本目录下的 `README.md`、`docs/URL_MODE.md`、`docs/AWVS.md`、`docs/SECOND_ORDER.md` 和 `docs/SECURITY_DESIGN.md`。
