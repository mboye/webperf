#!/usr/bin/env python
import argparse
import sys

DEBUG=False

parser = argparse.ArgumentParser()
parser.add_argument('root', help='Remove information about files outside this directory.')
parser.add_argument('coverage_info', help='Coverage file to strip.')
parser.add_argument('-d', '--dry-run', action='store_true', help='Do not modify coverage file.' )

params = parser.parse_args()

lines = open(params.coverage_info, 'r').read().split('\n')

if not params.dry_run:
    fp = open(params.coverage_info, 'w')

state = 'TN'
line_number = 0
skip_line = False
remove_count = 0


print >> sys.stderr, 'Root: {}'.format(params.root)


def print_line(line, skip_line):
    global fp
    global params
    if not skip_line and len(line) > 0:
        if not params.dry_run:
            fp.write('{}\n'.format(line));
        if DEBUG: print >> sys.stderr, 'Printing: {}'.format(line)
    else:
        if DEBUG: print >> sys.stderr, 'Removing: {}'.format(line)


print_tn = False
for line in lines:
    line_number += 1

    if line == 'TN:':
        print_tn = True
        continue
    elif line[0:2] == 'SF':
        if line[0:2] != 'SF':
            print 'Line {}: Expected SF'.format(line_number)
            sys.exit(1)
        else:
            path = line[3:]
            if not path.startswith(params.root):
                skip_line = True
                print >> sys.stderr, 'Stripping coverage information: {}'.format(path)
                remove_count += 1
            else:
                if print_tn:
                    print_line('TN:', False)
                    print_tn = False
            state = 'EOR'
    if state == 'EOR':
        print_line(line, skip_line)
        if line == 'end_of_record':
            state = 'TN'
            skip_line = False

print >> sys.stderr, 'Coverage information of {} files(s) were stripped.'.format(remove_count)
