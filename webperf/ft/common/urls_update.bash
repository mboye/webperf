#!/bin/bash
GET_URLS=../common/get_urls.js
URLS=/proj/webperf/ft/google_ncr.urls

if [ $# -ne 1 ]; then
	echo "Usage: update_urls.bash <URL>"
	exit 1
fi

update=0

if [ -f "$URLS" ]; then
	created=$(date -r "$URLS" +%s)
	now=$(date +%s)
	diff=$((now-created))
	if [ $diff -gt 3600 ]; then
		update=1
	fi
else
	update=1
fi

if [ $update -eq 1 ]; then
	echo "Updating URLs"
	"$GET_URLS" "$1" > "$URLS"
else
	echo "Skipping update of URLs"
fi
