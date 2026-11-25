#!/usr/bin/env python3

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.algos import partial_p
from RsaCtfTool.lib.coppersmith import CoppersmithError
from RsaCtfTool.lib.keys_wrapper import PrivateKey, PublicKey

class Attack(AbstractAttack):
    def __init__(self, timeout=60, p_high=None, p_unknown_bits=None):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]
        self.required_python_modules = ["sage.all"]
        self.p_high = p_high
        self.p_unknown_bits = p_unknown_bits

    def attack(self, publickey, cipher=[], progress=True):
        """
        Coppersmith partial p attack (Factoring N with high bits known).
        """
        if self.p_high is None:
            return None, None

        try:
            n = int(publickey.n)
            p_high = int(self.p_high)
            unknown_bits = (
                int(self.p_unknown_bits) if self.p_unknown_bits is not None else None
            )
        except (TypeError, ValueError):
            self.logger.warning("[!] Invalid --p-high or --p-unknown-bits parameter")
            return None, None

        if p_high <= 0:
            return None, None

        self.logger.info("[*] Performing partial p attack with high bits known...")

        try:
            p, q = partial_p(n, p_high, unknown_bits=unknown_bits)
            
            if p is not None and q is not None:
                self.logger.info("[+] partial_p attack found factorization")
                priv_key = PrivateKey(
                    n=n,
                    p=int(p),
                    q=int(q),
                    e=int(publickey.e),
                )
                return priv_key, None
                
            return None, None
        except CoppersmithError as exc:
            if "Sage" in str(exc):
                self.logger.info("[!] partial_p attack requires Sage dependency")
            else:
                self.logger.error(f"[!] partial_p attack failed: {exc}")
            return None, None
        except (ValueError, TypeError) as exc:
            self.logger.error(f"[!] partial_p attack failed: {exc}")
            return None, None

    def test(self):
        from RsaCtfTool.lib.crypto_wrapper import RSA

        p = int(
            "11814314815079808793202754845823415996236940468297640287934698158609319560359607901183228305190944525696915884370873052504610782679806230947564723036978431"
        )

        q = int(
            "6850324446788129079827624526540564637521699316237423751807524631616380311577742212267150797376483718097199550312926103390141403454742728224455964881423377"
        )

        n = p * q
        e = 65537

        pub_pem = RSA.construct((n, e)).publickey().exportKey()
        key = PublicKey(pub_pem)

        mask = (1 << 512) - (1 << 212)
        self.p_high = p & mask
        self.p_unknown_bits = 212

        priv, _ = self.attack(key, progress=False)

        return (
            priv is not None
            and priv.n == n
            and {int(priv.p), int(priv.q)} == {p, q}
        )
