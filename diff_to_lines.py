# Utility that converts a unified diff file (or standard in) into a format list the additions, with a line:
# filename:line_number
# for each line inserted in the diff

import fileinput
import sys
import re

new_path_re = re.compile("\+\+\+\s+(?P<path>[^\s]*)\s+.*")
indicator_re = re.compile("@@ \-([0-9]+),[0-9]+ \+(?P<new1>[0-9]+),(?P<new2>[0-9]+) @@")

cur_file = ""
cur_line = 1
if len(sys.argv) == 2:
    diffile = open(sys.argv[1])
else:
    diffile = fileinput.input()
for line in diffile:
    if new_path_re.match(line):
        match = new_path_re.match(line)
        cur_file = match.group("path")
        cur_file = cur_file[cur_file.rfind("/") + 1:]
    elif indicator_re.match(line):
        match = indicator_re.match(line)
        cur_line = int(match.group("new1"))
    elif line.startswith("+"):
        if cur_file.endswith(".c") or cur_file.endswith(".cc") or cur_file.endswith(".h") or cur_file.endswith(".hpp") or cur_file.endswith(".cpp"):
            print("%s:%i" % (cur_file, cur_line))
        cur_line += 1
    elif not line.startswith("-"):
        cur_line += 1

