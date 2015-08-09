#!/bin/bash
WEBPERF="${BUILD_DIR}/bin/webperf"
FT_COMMON="webperf/ft/common"
TMP="${BUILD_DIR}/ft/webperf"

PHANTOMJS="${CACHE_DIR}/bin/phantomjs"

TEST_DIR=$(dirname "${BASH_SOURCE[1]}")

mkdir -p "${TMP}"

update_urls()
{
    if [ $# -ne 2 ]; then
        echo "Usage: update_urls.sh <URL> <output>" 1>&2
        return 1
    fi

    url="$1"
    local file="$2"
    local max_age=3600

    if [ -f "$file" ]; then
        local update=0

        if [ "$(find $file -mmin +60 | wc -l)" -eq 1 ]
        then
            echo "Updating URLs because cached file is too old."
            update=1
        fi

        if [ "$(cat $file | wc -l)" -eq 0 ]
        then
            echo "Updating URLs because cached file is empty."
            update=1
        fi
    else
        echo "Updating URLs because cached file was not found."
        update=1
    fi

    if [ $update -eq 1 ]; then
        "$PHANTOMJS" --ignore-ssl-errors=true "${FT_COMMON}/get_urls.js" "$url" > "$file" 2>/dev/null
    fi
}
