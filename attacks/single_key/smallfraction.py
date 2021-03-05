#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging
import subprocess
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath

__SAGE__ = True


def attack(attack_rsa_obj, publickey, cipher=[]):
    """Code/idea from Renaud Lifchitz's talk 15 ways to break RSA security @ OPCDE17
    only works if the sageworks() function returned True
    """
    try:
        r = subprocess.check_output(
            ["sage", "%s/sage/smallfraction.sage" % rootpath, str(publickey.n)],
            timeout=attack_rsa_obj.args.timeout,
            stderr=subprocess.DEVNULL,
        )
        sageresult = int(r)
        if sageresult > 0:
            publickey.p = sageresult
            publickey.q = publickey.n // publickey.p
            priv_key = PrivateKey(
                int(publickey.p), int(publickey.q), int(publickey.e), int(publickey.n)
            )
            return (priv_key, None)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return (None, None)
    return (None, None)
