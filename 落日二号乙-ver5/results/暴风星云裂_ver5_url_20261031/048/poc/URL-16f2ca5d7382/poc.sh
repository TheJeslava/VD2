#!/usr/bin/env sh
set -eu
# Authorized testing only. Replace TARGET after review.
curl -sS -i -X POST 'http://TARGET:8080/048.php' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*' \
  -H 'Cookie: dvwaSession=1'
