#!/usr/bin/python
import sys, json

data = json.load(sys.stdin)
hashes = []
for element in data['elements']:
	hashes.append((element['hash'], element['url']))

for e in sorted(hashes):
	print e[0], e[1]
