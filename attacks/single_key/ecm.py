#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging
import subprocess
from lib.timeout import timeout
from lib.keys_wrapper import PrivateKey

__SAGE__ = True

logger = logging.getLogger("global_logger")


def attack(attack_rsa_obj, publickey, cipher=[]):
    """use elliptic curve method, may return a prime or may never return
       only works if the sageworks() function returned True
    """
    logger.warning(
        "[*] ECM Method can run forever and may never succeed, timeout set to %ssec. Hit Ctrl-C to bail out."
        % attack_rsa_obj.args.timeout
    )

    try:
        try:
            ecmdigits = attack_rsa_obj.args.ecmdigits
            dir_path = os.path.dirname(os.path.realpath(__file__))
            sagepath = os.path.join(dir_path, "../../sage/ecm.sage")
            if ecmdigits:
                sageresult = int(
                    subprocess.check_output(
                        ["sage", sagepath, str(publickey.n), str(ecmdigits)],
                        timeout=attack_rsa_obj.args.timeout,
                    )
                )
            else:
                sageresult = int(
                    subprocess.check_output(
                        ["sage", sagepath, str(publickey.n)],
                        timeout=attack_rsa_obj.args.timeout,
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
