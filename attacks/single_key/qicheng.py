#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging
import subprocess
from lib.timeout import timeout
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath

__SAGE__ = True

logger = logging.getLogger("global_logger")


def attack(attack_rsa_obj, publickey, cipher=[]):
    """Qi Cheng - A New Class of Unsafe Primes"""
    try:
        sageresult = int(
            subprocess.check_output(
                ["sage", "%s/sage/qicheng.sage" % rootpath, str(publickey.n)],
                timeout=attack_rsa_obj.args.timeout,
                stderr=subprocess.DEVNULL,
            )
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
        return (None, None)

    if sageresult > 0:
        p = sageresult
        q = publickey.n // sageresult
        priv_key = PrivateKey(int(p), int(q), int(publickey.e), int(publickey.n))
        return (priv_key, None)
    else:
        return (None, None)
