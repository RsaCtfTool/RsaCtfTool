#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from _primefac._prime import primes
from lib.keys_wrapper import PrivateKey


def attack(attack_rsa_obj, publickey, cipher=[]):
    """Try an attack where q < 100,000, from BKPCTF2016 - sourcekris
    """
    for prime in primes(100000):
        if publickey.n % prime == 0:
            publickey.q = prime
            publickey.p = publickey.n // publickey.q
            priv_key = PrivateKey(
                int(publickey.p), int(publickey.q), int(publickey.e), int(publickey.n)
            )
            return (priv_key, None)
    return (None, None)
