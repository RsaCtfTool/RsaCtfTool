#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.exceptions import FactorizationError
from RsaCtfTool.lib.number_theory import gcd

a = lambda n: int(str(n)[::-1])
b = lambda n: int(bin(n)[2:][::-1],2)
c = lambda n: int(oct(n)[2:][::-1],8)
d = lambda n: int(hex(n)[2:][::-1],16)

def FF(n):
    F = []
    for p in range(1,6):   
        np = pow(n, p)

        F.append(gcd(n, a(np)))
        F.append(gcd(n, b(np)))
        F.append(gcd(n, c(np)))
        F.append(gcd(n, d(np)))

        F.append(gcd(n, n ^ a(np)))
        F.append(gcd(n, n ^ b(np)))
        F.append(gcd(n, n ^ c(np)))
        F.append(gcd(n, n ^ d(np)))

    return list(set(filter(lambda x: n>x>1, F)))

class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run fermat attack with a timeout"""
        try:
            pq = FF(publickey.n)
            if len(pq) == 2:
                publickey.p, publickey.q = pq
            elif len(pq) == 1:
                publickey.p = pq[0]
                publickey.q = publickey.n // pq[0]
            elif len(pq) > 2 :
                self.logger.error("Multiprime RSA not supported...")       
            else:
                self.logger.error("No factors found...")  
                return None, None
        except:
            self.logger.error("Factorization error...")
            return None, None

        return self.create_private_key(publickey)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCG6ZYBPnfEFpkADglB1IDARrL3
Gk+Vs1CsGk1CY3KSPYpFYdlvv7AkBZWQcgGtMiXPbt7X3gLZHDhv+sKAty0Plcrn
H0Lr4NPtrqznzqMZX6MsHGCA2Q74U9Bt1Fcskrn4MQu8DGNaXiaVJRF1EDCmWQgW
VU52MDG8uzHj8RnGXwIDAQAB
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
