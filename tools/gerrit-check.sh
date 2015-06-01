#!/bin/bash
set -x
cd $WORKSPACE

code_review=0
verified=-1
COMMENTS="$WORKSPACE/review-comments.txt"

git log -1

"$WORKSPACE/tools/gerrit/detect-trailing-whitespace.sh" > $COMMENTS
if [ $(cat $COMMENTS | wc -l) -ne 0 ]; then
    code_review=-1
fi

export CC=clang
export CFLAGS="-Weverything -Wno-padded"
if make gerrit-check
then
    verified=1
fi

cppcheck --enable=all --inconclusive --xml --xml-version=2 */src */include 1>/dev/null 2> cppcheck.xml

export CODE_REVIEW=$code_review
export VERIFIED=$verified

cat $COMMENTS | $WORKSPACE/tools/gerrit/gerrit-post-review.py
