# POC — AWVS: Blind SQL Injection

- finding_id: `URL-23c44c1307c1`
- type: `blind_sql_injection` / CWE-89
- severity: `critical`
- file: `:0`

## 步骤

1. **Baseline request**  
```http
curl -sS -i -X GET 'http://TARGET:8080/039.php' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*' \
  -H 'Cookie: id=1'
```
预期：HTTP 200 and the normal application response.

2. **Replay the AWVS attack request (盲 SQL 注入)**  
```http
curl -sS -i -X GET 'http://TARGET:8080/039.php' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*' \
  -H 'Cookie: id=1'
```
预期：The boolean/time response differs from the baseline without direct data disclosure.

3. **Compare baseline and attack responses**  
预期：A security-relevant differential appears.

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。