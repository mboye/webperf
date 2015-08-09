#!/bin/bash
set -u

CODE_REVIEW=0
VERIFIED=-1

export BUILD_DIR=build

BUILD_LOG="${BUILD_DIR}/build.log"
FT_LOG="${BUILD_DIR}/ft.log"
QA_LOG="${BUILD_DIR}/quality.log"
REVIEW_COMMENTS="${BUILD_DIR}/review-comments.txt"

REVIEW_URL="${GERRIT_CHANGE_URL}/${GERRIT_PATCHSET_NUMBER}"

export CACHE_DIR=/proj/webperf/cache

if [ -d "${BUILD_DIR}" ]
then
    echo "Removing existing build directory '${BUILD_DIR}'"
    rm -rf "${BUILD_DIR}"
else
    mkdir -p "${BUILD_DIR}"
fi

# Check build
echo "Building everything..."
if ! make all > "${BUILD_LOG}" 2>&1
then
    echo "error: build failed."
    echo "log file: ${BUILD_LOG}"
    VERIFIED=-2
fi

# Check FT if build is OK
echo "Running functional tests..."
if [ $VERIFIED -eq -1 ]
then
    if make check_ft > "${FT_LOG}" 2>&1
    then
        VERIFIED=1
    else
        echo "error: one or more functional tests failed."
        echo "log file: ${FT_LOG}"
    fi
fi

# Check quality
echo "Checking code quality..."
if ! make REVIEW_COMMENTS="${REVIEW_COMMENTS}" check_whitespace \
    check_cppcheck > "${QA_LOG}" 2>&1
then
    echo "warning: code quality check failed."
    echo "check comments in Gerrit: ${REVIEW_URL}"
    code_review=-1
fi

echo "Posting Gerrit review..."
export CODE_REVIEW
export VERIFIED
cat "${REVIEW_COMMENTS}" | tools/gerrit/gerrit-post-review.py
if [ $? -ne 0 ]
then
    echo "error: failed to post Gerrit review."
    exit 1
fi

if [ $VERIFIED -ne 1 ]
then
    exit 1
else
    exit 0
fi
