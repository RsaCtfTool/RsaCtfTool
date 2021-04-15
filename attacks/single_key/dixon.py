#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.exceptions import FactorizationError
from lib.utils import timeout, TimeoutError
from gmpy2 import isqrt,gcd,next_prime

def dixon(N,B=7):
  def primes(B):
    p = 2
    tmp = [p]
    while p < B-1:
      p = next_prime(p)
      tmp.append(p)
    return tmp

  base = primes(B)
  start = isqrt(N)
  i = start

  i2N = []
  while i<=N:
    i2N.append(pow(i,2,N))
    i+=1

  basej2N = []
  for j in range(0,len(base)):
    basej2N.append(pow(base[j],2,N))

  for i in range(0,len(i2N)):
    for k in range(0,len(base)):
      if i2N[i] == basej2N[k]:
        f=gcd(start + i - base[k],N)
        if 1 < f < N:
          return f,N//f

  return  None,None

class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]
    def attack(self, publickey, cipher=[], progress=True):
        """Run fermat attack with a timeout"""
        try:
            with timeout(seconds=self.timeout):
                try:
                    if publickey.n <= 10**9:
                        publickey.p, publickey.q = dixon(publickey.n)
                    else:
                        logger.info("[-] Dixon is too slow for pubkeys > 10^10...")
                        return(None,None)
                except TimeoutError:
                    return (None, None)

        except FactorizationError:
            return (None, None)

        if publickey.p is not None and publickey.q is not None:
            try:
                priv_key = PrivateKey(
                    n=publickey.n,
                    p=int(publickey.p),
                    q=int(publickey.q),
                    e=int(publickey.e),
                )
                return (priv_key, None)
            except ValueError:
                return (None, None)

        return (None, None)

def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MB8wDQYJKoZIhvcNAQEBBQADDgAwCwIEA2fQNQIDAQAB
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
