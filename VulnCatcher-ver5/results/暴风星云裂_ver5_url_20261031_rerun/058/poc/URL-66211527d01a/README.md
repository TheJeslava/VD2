# POC — AWVS: Second-order SQL Injection

- finding_id: `URL-66211527d01a`
- type: `second_order_injection` / CWE-89
- severity: `critical`
- file: `:0`

## 步骤

1. **Baseline request**  
```http
curl -sS -i -X POST 'http://TARGET:8080/058.php' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary 'username=SafeText'
```
预期：HTTP 200 and the normal application response.

2. **Replay the AWVS attack request (二次注入)**  
```http
curl -sS -i -X POST 'http://TARGET:8080/058.php' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary 'username=sunset_user'
```
预期：The attack response differs from the baseline in status, length, or a security-relevant marker.

3. **Compare baseline and attack responses**  
预期：A security-relevant differential appears.

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。