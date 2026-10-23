#!/usr/bin/env python3

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.number_theory import gcd, powmod


def factor_from_faulty_signature(n, e, faulty_sig, msg=None, good_sig=None):
    """Bellcore attack on RSA-CRT signatures.

    A fault in one CRT half gives s' that is right mod p but wrong mod q,
    so gcd(s'^e - m, n) = p, or gcd(s - s', n) = p given the correct s.
    """
    candidates = []
    if msg is not None:
        candidates.append(powmod(faulty_sig, e, n) - msg)
    if good_sig is not None:
        candidates.append(good_sig - faulty_sig)
    for value in candidates:
        f = gcd(value % n, n)
        if 1 < f < n:
            return f
    return None


class Attack(AbstractAttack):
    def __init__(self, timeout=60, fault_sig=None, fault_msg=None, good_sig=None):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]
        self.fault_sig = fault_sig
        self.fault_msg = fault_msg
        self.good_sig = good_sig

    def attack(self, publickey, cipher=[], progress=True):
        """Factor n from a faulty RSA-CRT signature (--fault-sig with
        --fault-msg or --good-sig)"""
        if self.fault_sig is None or (self.fault_msg is None and self.good_sig is None):
            return None, None

        n, e = int(publickey.n), int(publickey.e)
        f = factor_from_faulty_signature(
            n,
            e,
            int(self.fault_sig),
            None if self.fault_msg is None else int(self.fault_msg),
            None if self.good_sig is None else int(self.good_sig),
        )
        if f is None:
            self.logger.info("[-] bellcore: the signature is not a CRT fault for this key")
            return None, None
        self.logger.info("[+] bellcore attack found factorization")
        return self.create_private_key_from_pqe(f, n // f, e, n)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        # examples/bellcore.pub
        key_data = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZOeRIKNUwNis2CPVZ7VOJ61fB
RzVs7NCGg7dNH5fOHK6NJgIhaekzwDGAYjbUwqVMj2AmtIlpGAd91dfTd+aiGdPY
6kgxddawk9vaBUB+ZdR2zcdI1XKrgoXKfiVZI9KO6gKfiNcCuxGn5bhwkiZGhpJg
N6H7p3Zib9b15wH3SwIDAQAB
-----END PUBLIC KEY-----"""
        p = 11534445604302728330865748355771474032510298894232540052601227005453731268150705978597846073879860561389929337598237897760398305592790398553719239614256999
        self.fault_msg = 0x1234567890ABCDEF
        self.fault_sig = 82515269436245477408654544426636384432311369156478430065940750442878664566979299782607409730886679851582144730406261916175604096113792348429783788025821898960581646534840780086061227577673632697821111609892168291094375015759054076054019618285596057026042753494235074772790622797665391121820944433211140045631
        self.good_sig = None
        priv, _ = self.attack(PublicKey(key_data), [])
        return priv is not None and p in (priv.p, priv.q)
