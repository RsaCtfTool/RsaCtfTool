#!/usr/bin/env sage

# reference https://github.com/comaeio/OPCDE/blob/master/15%20ways%20to%20break%20RSA%20security%20-%20Renaud%20Lifchitz/opcde2017-ds-lifchitz-break_rsa.pdf

import sys

n = int(sys.argv[1])
depth=50
t=len(bin(n).replace('0b',''))
nn = RealField(2000)(n)
p = 0

x = PolynomialRing(Zmod(n),"x").gen()

try:
    for den in xrange(2,depth+1):
      for num in xrange(1,den):
        if gcd(num,den)==1:
          r=Integer(den)/Integer(num);
          phint = int(sqrt(nn*r))
          f = x - phint
          sr = f.small_roots(beta=0.5)

          if len(sr)>0:
            p = int(phint - sr[0])
            if n%p==0:
              print(p)
              break
    if p == 0:
        print(p)
except:
    print(0)
    pass
