#!/bin/bash
for file in $(git diff --name-only HEAD~1..HEAD |
              awk '{ if($1 != "D") { print $2 }}')
do
    egrep -Hn "\s+$" "$file" |
        cut -d: -f1-2 |
        awk '{ printf("%s:%s\n", $0, "Trailing whitespace.") }'
done
