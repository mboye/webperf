#!/usr/bin/python
import json
import sys

try:
    json.load(open('webperf.output.json','r'))
    print "JSON integrity verified."
    sys.exit(0)
except Exception as e:
    print "JSON integrity check failed: {}".format(str(e))
    sys.exit(1)
