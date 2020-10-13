#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from rsactftool.lib.rsalibnum import gcd
from rsactftool.lib.keys_wrapper import PrivateKey

logger = logging.getLogger("global_logger")


def attack(attack_rsa_obj, publickeys, cipher=[]):
    """ Common factor attack
    """
    if not isinstance(publickeys, list):
        return (None, None)

    # Try to find the gcd between each pair of moduli and resolve the private keys if gcd > 1
    priv_keys = []
    tmp = 1
    for x in publickeys:
        tmp *= x.n
    for x in publickeys:
        g = gcd(x.n, tmp)
        if 1 < g < x.n:
            logger.info(
                "[*] Found common factor in modulus for "
                + x.filename
            )

            # update each attackobj with a private_key
            x.p = g
            x.q = x.n // g
            priv_key = PrivateKey(int(x.p), int(x.q), int(x.e), int(x.n))
            priv_keys.append(priv_key)
            
    priv_keys = list(set(priv_keys))
    if len(priv_keys) == 0:
        priv_keys = None

    return (priv_keys, None)
