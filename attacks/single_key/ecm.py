#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
    with timeout(seconds=attack_rsa_obj.args.timeout):
        try:
            try:
                ecmdigits = attack_rsa_obj.args.ecmdigits
                if ecmdigits:
                    sageresult = int(
                        subprocess.check_output(
                            [
                                "sage",
                                "./sage/ecm.sage",
                                str(publickey.n),
                                str(ecmdigits),
                            ]
                        )
                    )
                else:
                    sageresult = int(
                        subprocess.check_output(
                            ["sage", "./sage/ecm.sage", str(publickey.n)]
                        )
                    )
            except subprocess.CalledProcessError:
                return (None, None)
            if sageresult > 0:
                publickey.p = sageresult
                publickey.q = publickey.n // publickey.p
                priv_key = PrivateKey(
                    int(publickey.p),
                    int(publickey.q),
                    int(publickey.e),
                    int(publickey.n),
                )
                return (priv_key, None)
            return (None, None)
        except KeyboardInterrupt:
            return (None, None)
