# 集成数据集金标提示

本目录按 `../集成数据集/*.zip` 的样本名整理金标提示和答案参考，保留样本内的相对路径。

## DVWA

每个 DVWA 样本目录都包含对应模块的 `vulnerabilities/<module>/help/help.php`。该文件包含该模块所有安全等级的目标、提示、Spoiler，或 `Solution` / `Show Answer` 内容。`api` 和 `bac` 样本还保留了随包提供的模块 README。

明确包含 `Solution` / `Show Answer` 区块的模块是：

- `api`
- `bac`
- `cryptography`

其他模块的 `help.php` 主要是提示、Spoiler、示例请求或 payload，不保证存在单独的答案区块。

## SQLi-Labs Less-24

`sqli_labs_less24` 是二次注入样本。原 ZIP 中没有独立的 `answer`、`solution` 或 `result` 文件，因此没有把任何源码伪装成官方金标答案。目录中保留了可能用于复原金标流程的文件：

- `Less-24/*.php`：注册、登录、登录后改密等完整流程；
- `sql-connections/sql-connect.php`、`db-creds.inc`、`sql-lab.sql`：运行和数据库上下文；
- `PACKAGE_INFO.txt`：样本打包和部署说明；
- `images/`：Less-24 页面和结果截图，作为结果证据。

该样本的二次注入分析需要串起“注册写入 -> 登录建立会话 -> 登录后改密”的多个页面，不能只看 `Less-24/index.php`。

## 清单

- 来源样本：58 个 ZIP；
- DVWA 提示文件：57 个 `help.php`；
- API/BAC 模块 README：6 个；
- SQLi-Labs Less-24 参考文件：19 个（含页面源码、数据库上下文和截图）；
- 本目录不修改原始 ZIP，也不把帮助文本当作可执行样本。
