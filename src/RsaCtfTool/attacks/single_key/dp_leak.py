#!/usr/bin/env python3

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.keys_wrapper import PrivateKey, PublicKey
from RsaCtfTool.lib.number_theory import gcd, powmod


def factor_from_crt_exponent(n, e, d_crt):
    """Recover a factor of n from a leaked CRT exponent dp = d mod (p-1).

    e * dp = 1 (mod p-1), so m^(e*dp) = m (mod p) for any m, and
    gcd(m^(e*dp) - m, n) is p (or q, when dq is given).
    """
    for m in (2, 3, 5, 7, 11):
        f = gcd(powmod(m, e * d_crt, n) - m, n)
        if 1 < f < n:
            return f
    return None


class Attack(AbstractAttack):
    def __init__(self, timeout=60, dp=None, dq=None):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]
        self.dp = dp
        self.dq = dq

    def attack(self, publickey, cipher=[], progress=True):
        """Factor n from a leaked dp or dq (--dp / --dq)"""
        if self.dp is None and self.dq is None:
            return None, None

        n, e = int(publickey.n), int(publickey.e)
        for d_crt in (self.dp, self.dq):
            if d_crt is None or int(d_crt) <= 0:
                continue
            f = factor_from_crt_exponent(n, e, int(d_crt))
            if f is not None:
                self.logger.info("[+] dp_leak attack found factorization")
                priv_key = PrivateKey(n=n, p=int(f), q=int(n // f), e=e)
                return priv_key, None

        self.logger.info("[-] dp_leak: the leaked exponent does not match this key")
        return None, None

    def test(self):
        # examples/dp_leak.pub
        key_data = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDcRZK2cFeRPiWooo9ILxBmgRg3
LOEoDdIpwuOpRu19hbI4gL9DuQstY4DxQ6LDpn0f8A2rPujpZ6WV8Yl7tnjcf690
V3enFg4img1oZ03eKqJiOsuginKWNTM5o3gRvkDy1Ki7pvy9pue19WFPROUVEgOa
bNd4S8eKEa+oLOaASQIDAQAB
-----END PUBLIC KEY-----"""
        p = 11627817298186980362111459752942752021021230576363511644337672070728268584990759881962141686855271445585014216541705729870276496476779080747931969028077417
        self.dp = 8562290538065603938159161026859091349656889488147561048630418183030585984147414149924637924621947063376218030671012966992838754344460101283465048649251385
        priv, _ = self.attack(PublicKey(key_data), [])
        return priv is not None and p in (priv.p, priv.q)
