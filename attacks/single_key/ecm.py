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
    """use elliptic curve method, may return a prime or may never return
    only works if the sageworks() function returned True
    """

    try:
        try:
            ecmdigits = attack_rsa_obj.args.ecmdigits
            if ecmdigits:
                sageresult = int(
                    subprocess.check_output(
                        [
                            "sage",
                            "%s/sage/ecm.sage" % rootpath,
                            str(publickey.n),
                            str(ecmdigits),
                        ],
                        timeout=attack_rsa_obj.args.timeout,
                        stderr=subprocess.DEVNULL,
                    )
                )
            else:
                sageresult = int(
                    subprocess.check_output(
                        ["sage", "%s/sage/ecm.sage" % rootpath, str(publickey.n)],
                        timeout=attack_rsa_obj.args.timeout,
                        stderr=subprocess.DEVNULL,
                    )
                )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return (None, None)

        if sageresult > 0:
            publickey.p = sageresult
            publickey.q = publickey.n // publickey.p
            try:
                priv_key = PrivateKey(
                    int(publickey.p),
                    int(publickey.q),
                    int(publickey.e),
                    int(publickey.n),
                )
                return (priv_key, None)
            except:
                return (None, None)
        return (None, None)
    except KeyboardInterrupt:
        pass
    return (None, None)
