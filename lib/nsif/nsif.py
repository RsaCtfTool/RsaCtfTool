import math

def factor(n, base=3, limit=1000):
    logn = math.ceil(math.log(n)/math.log(base))
    fexp = base**logn
    for _ in range(logn-1):
      x = fexp
      for x in range(fexp,fexp+limit):
        if n % x == 0:
          return x
      fexp //= base


