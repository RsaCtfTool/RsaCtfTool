#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.algos import partial_p
from RsaCtfTool.lib.keys_wrapper import PrivateKey

class Attack(AbstractAttack):
    def __init__(self, timeout=60, p_high=None):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]
        self.p_high = p_high

    def attack(self, publickey, cipher=[], progress=True):
        """
        Coppersmith partial p attack (Factoring N with high bits known).
        """
        if self.p_high is None:
            return None, None

        try:
            n = int(publickey.n)
            p_high = int(self.p_high)
        except (TypeError, ValueError):
            self.logger.warning("[!] Invalid --p-high parameter")
            return None, None

        if p_high <= 0:
            return None, None

        self.logger.info("[*] Performing partial p attack with high bits known...")

        try:
            p, q = partial_p(n, p_high)
            
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
        except Exception as exc:
            self.logger.error(f"[!] partial_p attack failed: {exc}")
            return None, None

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey
        n = 10103734139880193134105432658825866164227306239169601614210080645607316139414594625574542861614947937397753696147493139818816434444080183149867086884639911 * 13197779919106263590458129202517036640822606828551139453738096181958434773489812423719918239272304919149791481136453186259836952873839211322237554904771617
        e = 65537
        key = PublicKey(n, e)
        p = 10103734139880193134105432658825866164227306239169601614210080645607316139414594625574542861614947937397753696147493139818816434444080183149867086884639911
        mask = (1 << 512) - (1 << 212)
        self.p_high = str(p & mask)
        
        priv, _ = self.attack(key, [])
        if priv is not None and priv.p == p:
            return True
        return False
