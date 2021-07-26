#!/usr/bin/env sage

# Use sage's built in Elliptic Curve Method for factorization of large composites

import sys

n = int(sys.argv[1])

try:
    if len(sys.argv) > 2:
        print(ecm.find_factor(n, int(sys.argv[2]))[0])
    else:
        print(ecm.find_factor(n)[0])
except:
    print(0)
