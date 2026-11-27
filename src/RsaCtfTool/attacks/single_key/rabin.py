#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.algos import nth_roots_mod_prime
from RsaCtfTool.lib.number_theory import chinese_remainder, gcd

logger = logging.getLogger("global_logger")

# Default number of candidates handed back; None returns all of them.
MAX_CANDIDATES = 16
# Refuse to build more CRT combinations than this.
MAX_COMBINATIONS = 1 << 16


def _nth_root_candidates(p, q, e, c, max_candidates=MAX_CANDIDATES):
    """Plaintexts m with m^e == c (mod p*q), for e sharing a factor with
    phi (e.g. Rabin, e = 2) so that no d exists.

    Returns (candidates, total): total is the number of roots found, so
    len(candidates) < total tells the caller the list was truncated.
    max_candidates=None returns every root.
    """
    if None in (p, q, e) or p == q:
        return [], 0
    roots_p = nth_roots_mod_prime(c, e, p)
    roots_q = nth_roots_mod_prime(c, e, q)
    if not roots_p or not roots_q:
        return [], 0
    total = len(roots_p) * len(roots_q)
    if total > MAX_COMBINATIONS:
        logger.warning(f"[!] {total} e-th root candidates, too many to build")
        return [], total
    msgs = []
    for a in roots_p:
        for b in roots_q:
            m = int(chinese_remainder([p, q], [a, b]))
            msgs.append(m.to_bytes(max(1, (m.bit_length() + 7) // 8), "big"))
    if max_candidates is not None and total > max_candidates:
        logger.warning(
            f"[!] {total} e-th root candidates, showing {max_candidates}"
        )
        msgs = msgs[:max_candidates]
    return msgs, total


class Attack(AbstractAttack):
    def __init__(self, timeout=60, max_candidates=MAX_CANDIDATES):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]
        self.max_candidates = max_candidates

    def attack(self, publickey, cipher=[], progress=True):
        """Decrypt when n is factored but e is not coprime with phi(n)
        (e.g. Rabin, e = 2): the plaintext is among the e-th roots of c
        mod p and mod q."""
        p, q = getattr(publickey, "p", None), getattr(publickey, "q", None)
        if not cipher or p is None or q is None:
            return None, None
        p, q, e = int(p), int(q), int(publickey.e)
        if gcd(e, (p - 1) * (q - 1)) == 1:
            return None, None
        plain = []
        for c in cipher:
            msgs, _ = _nth_root_candidates(
                p, q, e, int.from_bytes(c, "big"), self.max_candidates
            )
            plain += msgs
        return (None, plain) if plain else (None, None)

    def test(self):
        from types import SimpleNamespace

        p, q = 1000003, 1000039  # both 3 mod 4
        m = 123456789
        key = SimpleNamespace(n=p * q, e=2, p=p, q=q)
        c = pow(m, 2, p * q).to_bytes(6, "big")
        _, plain = self.attack(key, [c], progress=False)
        return plain is not None and m.to_bytes(4, "big") in plain
