# POC — 003.php 通过 REQUEST_URI 反射注入 JavaScript 上下文（DOM/反射型 XSS）

- finding_id: `LLM-d891d8de8c0d`
- type: `xss` / CWE-79
- severity: `high`
- file: `003.php:51`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/api/'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**  
```http
curl -sS -i -X GET 'http://TARGET:8080/vulnerabilities/api/'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。