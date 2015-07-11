#!/bin/bash
ROOT="$(git rev-parse --show-toplevel)"
WEBPERF="$ROOT/build/bin/webperf"
FT="$ROOT/webperf/ft"
FT_COMMON="$FT/common"

if [ -z "$FT_CACHE" ]; then
    export FT_CACHE="$ROOT/ft_cache"
    mkdir -p "$FT_CACHE"
    echo "FT cache: $FT_CACHE"
fi

if [ -z "$PHANTOMJS" ]
then
    echo "Environment variable PHANTOMJS not set."
    echo "Assuming phantomjs is in your PATH..."
    export PHANTOMJS="phantomjs"
fi

update_urls() {
    if [ $# -ne 2 ]; then
        echo "Usage: update_urls <URL> <output>" 1>&2
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
