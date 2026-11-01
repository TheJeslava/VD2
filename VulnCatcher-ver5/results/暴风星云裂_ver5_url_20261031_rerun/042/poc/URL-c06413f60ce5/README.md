# POC — AWVS: SQL Injection

- finding_id: `URL-c06413f60ce5`
- type: `sql_injection` / CWE-89
- severity: `critical`
- file: `:0`

## 步骤

1. **Baseline request**  
```http
curl -sS -i -X GET 'http://TARGET:8080/042.php?id=test' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*'
```
预期：HTTP 200 and the normal application response.

2. **Replay the AWVS attack request (SQL 注入)**  
```http
curl -sS -i -X GET 'http://TARGET:8080/042.php?id=1' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*'
```
预期：The response contains a SQL error or a different row set than the baseline.

3. **Compare baseline and attack responses**  
预期：A security-relevant differential appears.

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。