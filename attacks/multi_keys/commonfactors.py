#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import itertools
from lib.rsalibnum import gcd
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError

logger = logging.getLogger("global_logger")


def attack(attack_rsa_obj, publickeys, cipher=[]):
    """Common factor attack"""
    if not isinstance(publickeys, list):
        return (None, None)

    with timeout(attack_rsa_obj.args.timeout):
        try:
            # Try to find the gcd between each pair of moduli and resolve the private keys if gcd > 1
            priv_keys = []
            for x, y in itertools.combinations(publickeys, r=2):
                if x.n != y.n:
                    g = gcd(x.n, y.n)
                    if g != 1:

                        try:
                            # update each attackobj with a private_key
                            x.p = g
                            x.q = x.n // g
                            y.p = g
                            y.q = y.n // g
                            priv_key_1 = PrivateKey(
                                int(x.p), int(x.q), int(x.e), int(x.n)
                            )
                            priv_key_2 = PrivateKey(
                                int(y.p), int(y.q), int(y.e), int(y.n)
                            )
                            priv_keys.append(priv_key_1)
                            priv_keys.append(priv_key_2)

                            logger.info(
                                "[*] Found common factor in modulus for "
                                + x.filename
                                + " and "
                                + y.filename
                            )
                        except ValueError:
                            continue
        except TimeoutError:
            return (None, None)

    priv_keys = list(set(priv_keys))
    if len(priv_keys) == 0:
        priv_keys = None

    return (priv_keys, None)
