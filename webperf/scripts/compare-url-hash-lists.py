#!/usr/bin/python
import sys

run_a = open(sys.argv[1]).readlines()
run_b = open(sys.argv[2]).readlines()

url_hash_a = []
def parse_lines(lines):
	result = []
	for line in lines:
		line = line.strip()
		parts = line.split(' ')
		hash = parts[0]
		url = line[len(hash)+1:]
		result.append((hash, url))
	return result

A = parse_lines(run_a)
B = parse_lines(run_b)
dB = dict(B)

print "Number of elements: %d ~ %d" % (len(A), len(B))

for hu in A:
	hash = hu[0]
	url = hu[1]
	if hash in dB:
		b_url = dB[hash]
		if url == b_url:
			print hash, "FOUND", "URL MATCH"
		else:
			print hash, "FOUND"
			print url
			print b_url
			print
