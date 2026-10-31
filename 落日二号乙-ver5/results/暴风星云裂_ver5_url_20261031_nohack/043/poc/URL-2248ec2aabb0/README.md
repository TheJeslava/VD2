# POC — AWVS: Unrestricted File Upload

- finding_id: `URL-2248ec2aabb0`
- type: `file_upload` / CWE-434
- severity: `critical`
- file: `:0`

## 步骤

1. **Baseline request**  
```http
curl -sS -i -X POST 'http://TARGET:8080/043.php' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*' \
  -H 'Content-Type: multipart/form-data; boundary=----SunsetAWVSProbeBoundary' \
  --data-binary '------SunsetAWVSProbeBoundary
Content-Disposition: form-data; name="uploaded"; filename="SafeText"
Content-Type: text/plain

SUNSET_SAFE_UPLOAD
------SunsetAWVSProbeBoundary--'
```
预期：HTTP 200 and the normal application response.

2. **Replay the AWVS attack request (不安全文件上传)**  
```http
curl -sS -i -X POST 'http://TARGET:8080/043.php' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*' \
  -H 'Content-Type: multipart/form-data; boundary=----SunsetAWVSProbeBoundary' \
  --data-binary '------SunsetAWVSProbeBoundary
Content-Disposition: form-data; name="uploaded"; filename="sunset.txt"
Content-Type: text/plain

SUNSET_SAFE_UPLOAD
------SunsetAWVSProbeBoundary--'
```
预期：The attack response differs from the baseline in status, length, or a security-relevant marker.

3. **Compare baseline and attack responses**  
预期：A security-relevant differential appears.

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。