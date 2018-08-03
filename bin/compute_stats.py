#!/usr/bin/env python3

import sys
import argparse
import os
import os.path
import re

regex = re.compile(r'^(\d+):(\d\d):(\d\d)\.(\d+)$')
alt_regex = re.compile(r'^(\d+):(\d\d):(\d\d)$')

count = 0
total = 0.0
_max = 0.0
_min = 100000
minimum_considered = 1.0
excluded = 0

for line in sys.stdin:
    if count == 1000000:
        break

    m = regex.match(line.strip())
    if m:
        hour, minute, second, frac = m.groups()
    else:
        m = alt_regex.match(line.strip())
        if m:
            hour, minute, second = m.groups()
            frac = "000000"
        else:
            sys.stderr.write("ERROR: line {} in {} failed regex\n".format(line.strip(), stats_file))
            continue

    total_seconds = float('0.{}'.format(frac)) + float(second) + (float(minute) * 60.0) + (float(hour) * 60.0 * 60.0)
    if total_seconds < minimum_considered:
        excluded += 1
        continue

    total += total_seconds
    count += 1
    if total_seconds > _max:
        _max = total_seconds
    if total_seconds < _min:
        _min = total_seconds

if count:
    print("total {} averge {:.2f} max {:.2f} min {:.2f} (excluded {})".format(count, total / float(count), _max, _min, excluded))
