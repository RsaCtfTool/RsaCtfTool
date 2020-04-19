#!/usr/bin/env sage

# Use sage's built in Elliptic Curve Method for factorization of large composites

import sys

n = int(sys.argv[1])

try:
    print(ecm.factor(n))
except:
    print(0)
