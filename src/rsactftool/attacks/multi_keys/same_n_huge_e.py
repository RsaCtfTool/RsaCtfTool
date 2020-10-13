#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import tempfile
from Crypto.PublicKey import RSA
from rsactftool.lib.keys_wrapper import PublicKey


def attack(attack_rsa_obj, publickey, cipher=[]):
    """ Same n huge e attack
    """
    if not isinstance(publickey, list):
        return (None, None)

    if len(set([_.n for _ in publickey])) == 1:
        new_e = 1
        for k in publickey:
            new_e = new_e * k.e
        tmpfile = tempfile.NamedTemporaryFile()
        with open(tmpfile.name, "wb") as tmpfd:
            tmpfd.write(RSA.construct((publickey[0].n, new_e)).publickey().exportKey())
            result = attack_rsa_obj.attack_single_key(tmpfile.name)
            if result:
                return (attack_rsa_obj.priv_key, None)
    return (None, None)
