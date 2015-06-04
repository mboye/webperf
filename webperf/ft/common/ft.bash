#!/bin/bash
ROOT="$(git rev-parse --show-toplevel)"
WEBPERF="$ROOT/webperf/webperf"
FT="$ROOT/webperf/ft"
FT_COMMON="$FT/common"

update_urls() {
    if [ $# -ne 2 ]; then
        echo "Usage: update_urls <URL> <output>" 1>&2
        return 1
    fi

    url="$1"
    local file="$2"
    local max_age=3600

    if [ -f "$file" ]; then
        local created=$(date -r "$file" +%s)
        local now=$(date +%s)
        local diff=$((now-created))

        local update=0
        [ "$diff" -gt "${max_age}" ] && update=1
        [ $(wc -l $file | cut -d' ' -f1) -eq 0 ] && update=1
    else
        update=1
    fi

    if [ $update -eq 1 ]; then
        echo "Updating target elements of '$url' ..."
        "${FT_COMMON}/get_urls.js" "$url" > "$file"
    fi
}
