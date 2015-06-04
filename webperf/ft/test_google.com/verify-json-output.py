#!/usr/bin/python
import json
import sys

try:
    data = json.load(open('webperf.output.json','r'))
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

    print "JSON integrity verified."
    sys.exit(0)
except Exception as e:
    print "error: JSON integrity check failed: {}".format(str(e))
    sys.exit(1)
