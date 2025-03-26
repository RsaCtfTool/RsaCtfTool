import sys
n = int(sys.argv[1])
if len(str(n)) >= 40:
  pq, z = qsieve(n)
  p, q = pq
  print(p, q)
else:
  p,q = factor(n)
  print(p[0],q[0])

