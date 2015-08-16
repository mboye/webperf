#!/usr/bin/python
import requests
import json
import sys
import os

required_variables = ['GERRIT_CHANGE_ID', 'GERRIT_PATCHSET_REVISION',
    'CODE_REVIEW', 'VERIFIED', 'BUILD_URL', 'GERRIT_HTTP_AUTH' ]

abort = False
for env_var in required_variables:
    if not env_var in os.environ:
        print "Required environment variable '{}' missing.".format(env_var)
        abort = True


if abort:
    sys.exit(1)

change_id = os.environ['GERRIT_CHANGE_ID']
revision_id = os.environ['GERRIT_PATCHSET_REVISION']
code_review = int(os.environ['CODE_REVIEW'])
verified = int(os.environ['VERIFIED'])
build_url = os.environ['BUILD_URL']
gerrit_http_auth = os.environ['GERRIT_HTTP_AUTH']

url='http://localhost:8080/a/changes/{}/revisions/{}/review'.format(change_id, revision_id)
user=('jenkins', gerrit_http_auth)

if verified != 1:
    message = 'Build Failed\n{} : FAIL'.format(build_url)
else:
    message = 'Build Successful\n{} : SUCCESS'.format(build_url)

review = {}
review['message'] = message
review['labels'] = { 'Code-Review': code_review, 'Verified': verified }

files = {}
comments = 0

for line in sys.stdin.readlines():
    parts = line.strip().split(':')
    path = parts[0]
    line_number = parts[1]
    comment = ':'.join(parts[2:])
    if path in files:
        files[path].append({'line': line_number, 'message': comment })
    else:
        files[path] = [ {'line': line_number, 'message': comment } ]

    comments += 1

if comments > 0:
    review['comments'] = files

requests.post(url,
        headers={'Content-Type': 'application/json; charset=UTF-8'},
        auth=user,
        data=json.dumps(review))

print "{} comment(s) posted to Gerrit.".format(comments)

sys.exit(0)
