#!/usr/bin/python
import json, sys
from sets import Set

data = json.load(open(sys.argv[1]))
elements = data['elements']
e_index = {}
roots = Set()

for e in elements:
	hash = e['hash']
	e_index[hash] = e

def has_redirector(e):
	return 'http' in e and  'redirector' in e['http']

def get_redirector(e):
	return e['http']['redirector']

def trace_redir(hash, stack):
	e = e_index[hash]
	stack.append(e['url'])
	if has_redirector(e):
		trace_redir(get_redirector(e), stack)
	else:
		if len(stack) == 1:
			return
		for url in reversed(stack): 
			print url

def find_redir_root(hash):
	e = e_index[hash]
	if has_redirector(e):
		find_redir_root(get_redirector(e))
	else:
		roots.add(e['hash'])

def print_redir_path(hash, step):
	e = e_index[hash]
	print "step %d: %s" % (step, e['url'])
	step += 1
	if 'http' in e and 'redirectee' in e['http']:
		print_redir_path(e['http']['redirectee'], step)

for e in elements:
	find_redir_root(e['hash'])

for hash in roots:
	print_redir_path(hash, 1)
	print
