#!/bin/bash
set -e
set -x

source "$(git rev-parse --show-toplevel)/webperf/ft/common/ft.bash"

URL=https://www.google.com/ncr
TARGETS="/proj/webperf/ft/google.com.urls"

update_urls "$URL" "$TARGETS"

CONF=webperf.conf.tmp
cp webperf.conf $CONF


echo "dns.loadCache=${FT_COMMON}/root_servers.cache" >> $CONF
echo "http.CAFile=${FT_COMMON}/ca-certs.pem" >> $CONF
echo "test.loadURLs=$TARGETS" >> $CONF

$WEBPERF "$CONF" "webperf.output" > "webperf.stdout" 2>"webperf.stderr"
./verify-json-output.py