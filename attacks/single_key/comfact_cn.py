#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from lib.rsalibnum import s2n, gcd
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError


def comfact(cipher, publickey):
    for c in cipher:
        commonfactor = gcd(publickey.n, s2n(c))

        if commonfactor > 1:
            publickey.q = commonfactor
            publickey.p = publickey.n // publickey.q
            priv_key = PrivateKey(
                int(publickey.p),
                int(publickey.q),
                int(publickey.e),
                int(publickey.n),
            )
            return (priv_key, None)
    return (None, None)


def attack(attack_rsa_obj, publickey, cipher=[]):
    """Try an attack where the public key has a common factor with the ciphertext - sourcekris"""
    timeout_delay = attack_rsa_obj.args.timeout
    if cipher is not None:
        try:
            with timeout(attack_rsa_obj.args.timeout):
                return comfact(cipher, publickey)
        except TimeoutError:
            return (None, None)
    return (None, None)
