#!/usr/bin/env python
import sys
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('genhtml_log', help='Output from genhtml.')

params = parser.parse_args()

state = 'bgof_coverage'
line_coverage = 0
function_coverage = 0

for line in open(params.genhtml_log).readlines():
    if state == 'bgof_coverage' and 'Overall coverage rate:' in line:
        state = 'line_coverage'
    elif state == 'line_coverage':
        parts = line.strip().split(' ')
        line_coverage = float(parts[1][:-1])
        state = 'function_coverage'
    elif state == 'function_coverage':
        parts = line.strip().split(' ')
        function_coverage = float(parts[1][:-1])
        state = 'function_coverage'
        break

print '"Lines"', '"Functions"'
print line_coverage, function_coverage
