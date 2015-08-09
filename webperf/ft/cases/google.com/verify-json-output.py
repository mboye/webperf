#!/usr/bin/python
import json
import sys

print "Validating test results..."

try:
    data = json.load(open(sys.argv[1], 'r'))
    download_time_sum = 0
    for element in data['elements']:
        http = element['http']
        if not 'downloadTime' in http:
            print "error: elements.http.downloadTime missing."
            sys.exit(1)
        download_time_sum += http['downloadTime']

    if download_time_sum == 0:
        print "error: sum of all downloadTimes is zero."
        sys.exit(1)

    print "Test results verified."
    sys.exit(0)
except Exception as e:
    print "error: JSON integrity check failed: {}".format(str(e))
    sys.exit(1)
