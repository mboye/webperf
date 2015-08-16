#!/usr/bin/env python
import argparse
import re
import json
import os
import sys


class Warning(object):
    def __init__(self, path, line, column, type, message):
        self.path = path
        self.type = type
        self.message = message

        try:
            self.line = int(line)
        except:
            self.line = None

        try:
            self.column = int(column)
        except:
            self.column = None

    def json(self):
        warning = { 'path': self.path,
                    'line': self.line,
                    'column': self.column,
                    'type': self.type,
                    'message': self.message }
        return warning

    def __hash__(self):
        return hash((self.path, self.column, self.type, self.message))

    def __str__(self):
        location = ''
        if self.line:
            location += ':{}'.format(self.line)
        if self.column:
            location += ':{}'.format(self.column)

        return '{}{} {}: {}'.format(self.path, location, self.type, self.message)


    def __eq__(self, other):
        return (self.path == other.path and
                self.column == other.column and
                self.type == other.type and
                self.message == other.message)

def main():
    params = parse_arguments()

    sanity_check(params)

    warnings = find_warnings(params.log)

    if params.baseline:
        baseline_warnings = find_warnings(params.baseline)
        compare_warnings(warnings, baseline_warnings, params.print_remaining)
    else:
        print_warnings(warnings)


def sanity_check(params):
    if not os.path.isfile(params.log):
        print "Could not find build log '{}'".format(params.log)
        sys.exit(1)

    if params.baseline:
        if not os.path.isfile(params.baseline):
            print "Could not find baseline log '{}'".format(params.baseline)
            sys.exit(1)

def compare_warnings(warnings, baseline_warnings, print_remaining):
    fixed_warnings = []
    remaining_warnings = []
    for bw in baseline_warnings:
        if not bw in warnings:
            fixed_warnings.append(bw)
        else:
            remaining_warnings.append(bw)

    new_warnings = []
    for w in warnings:
        if not w in baseline_warnings:
            new_warnings.append(w)

    if len(fixed_warnings) > 0:
        print 'Fixed warnings: {}'.format(len(fixed_warnings))
        for warning in fixed_warnings:
            print warning
        print

    if len(new_warnings) > 0:
        print 'New warnings: {}'.format(len(new_warnings))
        for w in new_warnings:
            print w
        print


    if len(remaining_warnings) > 0 and print_remaining:
        print 'Remaining warnings: {}'.format(len(remaining_warnings))
        for w in remaining_warnings:
            print w
        print

    print 'Fixed warnings: {}'.format(len(fixed_warnings))
    print 'New warnings: {}'.format(len(new_warnings))
    print 'Remaining warnings: {}'.format(len(remaining_warnings))

def print_warnings(warnings):
    errors = [ w for w in warnings if w.type == 'error' ]
    warnings = [ w for w in warnings if w.type == 'warning' ]

    if len(warnings) > 0:
        for warning in warnings:
            print warning

    if len(errors) > 0:
        for error in errors:
            print error

    if len(errors) == 0 and len(warnings) == 0:
        print 'No errors or warnings detected.'
    else:
        print
        print '{} error(s) found.'.format(len(errors))
        print '{} warning(s) found.'.format(len(warnings))


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('log', help='Build log file.')

    parser.add_argument('--baseline', '-b',
                        help='Baseline build log to compare against.')

    parser.add_argument('--print-remaining', '-r',
                        action='store_true',
                        help='Print remaining warnings.')

    parser.add_argument('--json',
                        help='Save errors and warnings to JSON file.')

    return parser.parse_args()

def find_warnings(log_file):
    matcher = re.compile('(.*):(\d*):(\d*):\s(warning|error): (.*)')

    log_data = open(log_file).read()
    warnings = []
    for match in matcher.findall(log_data):
        warning = Warning(match[0], match[1], match[2], match[3], match[4])
        warnings.append(warning)

    return warnings

def save_json(warnings, output_path):
    if params.json:
        open(output_path, 'w').write(json.dumps(warnings))

if __name__ == '__main__':
    main()
