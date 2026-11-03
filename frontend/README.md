# VulnCatcher 工作台

在 VD2 仓库根目录启动工作台，需要 Python 3.10 或更新版本。

```sh
python3 frontend/server.py
```

Windows 可用 `py -3 frontend/server.py`。打开 <http://127.0.0.1:8765/>。同一进程提供页面和任务 API，每次扫描或验证启动独立 Python 子进程，直接导入仓库中的 `VulnCatcher-ver5/sunset` 和 `VulnCatcher-Verify/sunset_verify`。页面轮询任务进度，显示引擎记录的模块状态、报告、POC 和验证结论。

## 操作

- **ZIP**。选择源码包（最大 32 MiB），或者使用「载入示例 ZIP」，点击「开始挖掘」。示例按钮会加载实际 ZIP 文件，和手动选择的文件进入相同管线。
- **URL**。输入已授权的 HTTP(S) 目标，运行 URL 管线。配置 AWVS API 后使用该服务。缺省使用项目内置的 AWVS 兼容探针，在给定端点上检测查询参数的 XSS 和 SQL 注入信号。精确匹配自定义探针清单时使用清单中的参数与检测类型。
- **ZIP + URL**。在 ZIP 模式补填目标 URL。工作台将动态证据交给源码管线，由其关联并生成本次报告。
- **验证**。挖掘完成后点击「验证漏洞」。纯 ZIP 需要填写已部署的授权靶场地址。VulnCatcher-Verify 从本次扫描的输出收集 POC 并执行 HTTP 验证。基线、探测响应与判定均来自该次验证。
- **设置**。可切换可选模块、全局 LLM 和各智能体的 LLM。默认关闭模型调用。启用 LLM 时，沿用引擎的 `SUNSET_LLM_API_KEY`、`SUNSET_LLM_MODEL`、`SUNSET_LLM_BASE_URL` 等配置。也可显式设置 `SUNSET_ENV_FILE` 指向自己的配置文件。AWVS API 使用 `SUNSET_AWVS_URL` 与 `SUNSET_AWVS_KEY`，可通过 `SUNSET_AWVS_MANIFEST` 指定本地探针清单的绝对路径。
- **历史**。每次任务在 `vulncatcher-results/workbench/<任务 ID>/` 保留输入 ZIP、状态与报告。挖掘产物在 `scan/`，验证产物在 `scan/verification/`。服务重启后可从任务历史重新打开。支持 `--data` 指定存储目录、`--port` 指定端口。

「样例档案」是单独的只读区域。双击 HTML 或使用纯静态托管时可以浏览该区域；提交真实任务需从上述本地服务打开工作台。
