#!/usr/bin/env sh
set -eu
# Authorized testing only. Replace TARGET after review.
curl -sS -i -X POST 'http://TARGET:8080/057.php' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary 'txtName=SafeText'
