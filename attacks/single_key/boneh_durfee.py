#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging
import subprocess
from Crypto.PublicKey import RSA
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath

__SAGE__ = True


def attack(attack_rsa_obj, publickey, cipher=[]):
    """Use boneh durfee method, should return a d value, else returns 0
    only works if the sageworks() function returned True
    many of these problems will be solved by the wiener attack module but perhaps some will fall through to here
    """
    try:
        sageresult = int(
            subprocess.check_output(
                [
                    "sage",
                    "%s/sage/boneh_durfee.sage" % rootpath,
                    str(publickey.n),
                    str(publickey.e),
                ],
                timeout=attack_rsa_obj.args.timeout,
                stderr=subprocess.DEVNULL,
            )
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return (None, None)
    if sageresult > 0:
        tmp_priv = RSA.construct((int(publickey.n), int(publickey.e), int(sageresult)))
        publickey.p = tmp_priv.p
        publickey.q = tmp_priv.q
        privatekey = PrivateKey(
            p=int(publickey.p),
            q=int(publickey.q),
            e=int(publickey.e),
            n=int(publickey.n),
        )
        return (privatekey, None)
    return (None, None)
