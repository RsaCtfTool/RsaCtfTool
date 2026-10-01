#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import os
from RsaCtfTool.attacks.abstract_attack import AbstractAttack, SAGE_MIN_TIMEOUT
from RsaCtfTool.lib.utils import rootpath, TimeoutError, terminate_proc_tree


class Attack(AbstractAttack):
    def __init__(self, timeout=60, ecmdigits=25):
        super().__init__(max(timeout, SAGE_MIN_TIMEOUT))
        self.speed = AbstractAttack.speed_enum["slow"]
        self.required_binaries = ["sage"]
        self.required_scripts = ["sage/ecm.sage"]
        self.ecmdigits = ecmdigits

    def attack(self, publickey, cipher=[], progress=True):
        """use elliptic curve method, may return a prime or may never return
        only works if the sageworks() function returned True
        """

        path_to_sage_interface = f"{rootpath}/sage/ecm.sage"
        sage_find_factor_n = str(publickey.n)

        try:
            if self.ecmdigits is not None:
                sage_find_factor_cmd = [
                    "sage",
                    path_to_sage_interface,
                    sage_find_factor_n,
                    str(self.ecmdigits),
                ]
            else:
                sage_find_factor_cmd = [
                    "sage",
                    path_to_sage_interface,
                    sage_find_factor_n,
                ]

            sage_proc = subprocess.Popen(
                sage_find_factor_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                # Own session: os.getpgid(child) then names the child
                # itself, so the timeout cleanup below cannot escalate to
                # killing this tool's own process group.
                start_new_session=True,
            )
            try:
                sage_proc.wait(timeout=self.timeout)
                stdout, stderr = sage_proc.communicate()
                try:
                    sageresult = int(stdout)
                except ValueError:
                    # sage died before printing a factor (empty or garbled
                    # stdout); treat it as a miss instead of raising.
                    return (None, None)
            except (
                subprocess.CalledProcessError,
                subprocess.TimeoutExpired,
                TimeoutError,
            ):
                terminate_proc_tree(os.getpgid(sage_proc.pid))
                return (None, None)

            # Accept only a genuine factor split: the script prints 0 on
            # failure and may echo n itself for prime input.
            if 1 < sageresult < publickey.n and publickey.n % sageresult == 0:
                p = sageresult
                rem = publickey.n // p
                from RsaCtfTool.lib.number_theory import is_prime, recursive_factorize

                if is_prime(rem):
                    publickey.p = p
                    publickey.q = rem
                    return self.create_private_key_from_pqe(
                        publickey.p, publickey.q, publickey.e, publickey.n
                    )
                else:
                    sub_primes = recursive_factorize(rem)
                    all_primes = [p] + sub_primes
                    import functools

                    if (
                        functools.reduce(lambda x, y: x * y, all_primes, 1)
                        == publickey.n
                    ):
                        return self.create_private_key_from_primes(
                            all_primes, publickey.e, publickey.n
                        )
            return (None, None)
        except KeyboardInterrupt:
            pass
        return (None, None)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgRBNZTe9G/tNqNNwNZz4JDgmOVmk
ZheJybt5Ew4jKnUjKcfLY8rs8nGCbVdYyKUdq3WQSKCsYy2StxBSZn4qgxoA7G5n
DGWWBFisWHeLM+lUr3jfnOTbnAZt3utu8plSMbv2irXohbDRxN/6NgzoQMVcmhIQ
bD3qa8mMScpXZXD2qwIDAQAB
-----END PUBLIC KEY-----"""
        self.timeout = 180
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
