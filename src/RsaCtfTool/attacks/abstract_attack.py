#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
from pathlib import Path
import sys
from typing import List, Any, Optional, Tuple
import shutil
from RsaCtfTool.lib.utils import timeout, TimeoutError

# Package root (the directory containing the sage/ helper scripts),
# used to resolve declared helper scripts.
_ROOTPATH = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Sage-backed attacks pay interpreter startup plus lattice/ECM/QS runtimes
# that the bare 60s CLI default cuts short; give them the same 180s budget
# the heavier pure-Python attacks (dixon, quadratic_sieve, pollard_rho) use.
# qicheng keeps its own higher floor (900s).
SAGE_MIN_TIMEOUT = 180


class AbstractAttack(object):
    speed_enum = {"slow": 0, "medium": 1, "fast": 2}

    def __init__(self, timeout: int = 60):
        self.logger = logging.getLogger("global_logger")
        self.speed = AbstractAttack.speed_enum["medium"]
        self.timeout = timeout
        self.required_binaries = []
        # Helper scripts (relative to the repository root) that must exist
        # for the attack to run; e.g. "sage/boneh_durfee.sage".
        self.required_scripts = []

    def get_name(self) -> str:
        """Return attack name"""
        full_path = sys.modules[self.__class__.__module__].__file__
        return Path(full_path).name.split(".")[0]

    def can_run(self) -> bool:
        """Test if everything is ok for running attack"""
        for required_binary in self.required_binaries:
            if shutil.which(required_binary) is None:
                self.logger.warning(
                    f"Can't load {self.get_name()} because {required_binary} binary is not installed"
                )
                return False
        for required_script in self.required_scripts:
            script_path = os.path.join(_ROOTPATH, required_script)
            if not os.path.isfile(script_path):
                self.logger.warning(
                    f"Can't load {self.get_name()} because helper script "
                    f"{required_script} is missing"
                )
                return False
        return True

    def attack(
        self,
        publickeys: List[Any],
        cipher: Optional[List[Any]] = None,
        progress: bool = True,
    ) -> Tuple[Optional[Any], Optional[Any]]:
        """Attack implementation"""
        if cipher is None:
            cipher = []
        raise NotImplementedError

    def attack_wrapper(
        self,
        publickeys: List[Any],
        cipher: Optional[List[Any]] = None,
        progress: bool = True,
    ) -> Tuple[Optional[Any], Optional[Any]]:
        """Attack wrapper to include timer in all attacks"""
        with timeout(self.timeout):
            try:
                return self.attack(publickeys, cipher, progress)
            except TimeoutError:
                self.logger.warning(f"[!] Timeout during {self.get_name()} attack.")
                return None, None

    def test(self) -> None:
        """Attack test case"""
        raise NotImplementedError

    def create_private_key(self, publickey) -> Tuple[Optional[Any], Optional[Any]]:
        """Helper method to create a private key from publickey with p, q, or primes

        Args:
            publickey: PublicKey object with n, e, p, q (or primes) attributes

        Returns:
            Tuple of (PrivateKey, None) on success or (None, None) on failure
        """
        from RsaCtfTool.lib.keys_wrapper import PrivateKey

        if (
            hasattr(publickey, "primes")
            and publickey.primes
            and len(publickey.primes) > 2
        ):
            return self.create_private_key_from_primes(
                publickey.primes, publickey.e, publickey.n
            )

        if publickey.p is not None and publickey.q is not None:
            try:
                priv_key = PrivateKey(
                    n=publickey.n,
                    p=int(publickey.p),
                    q=int(publickey.q),
                    e=int(publickey.e),
                )
                if priv_key.key is None and priv_key.d is None:
                    return None, None
                return priv_key, None
            except (ValueError, TypeError):
                return None, None
        return None, None

    def create_private_key_from_pqe(
        self, p, q, e, n
    ) -> Tuple[Optional[Any], Optional[Any]]:
        """Helper method to create a private key from p, q, e, n values

        Args:
            p: prime factor p
            q: prime factor q
            e: public exponent e
            n: modulus n

        Returns:
            Tuple of (PrivateKey, None) on success or (None, None) on failure
        """
        from RsaCtfTool.lib.keys_wrapper import PrivateKey

        if p is not None and q is not None:
            try:
                priv_key = PrivateKey(p=int(p), q=int(q), e=int(e), n=int(n))
                if priv_key.key is None and priv_key.d is None:
                    return None, None
                return priv_key, None
            except (ValueError, TypeError):
                return None, None
        return None, None

    def create_private_key_from_primes(
        self, primes, e, n
    ) -> Tuple[Optional[Any], Optional[Any]]:
        """Helper method to create a private key from an arbitrary list of prime factors

        Args:
            primes: list of prime factors (e.g. [p1, p2, p3, p4])
            e: public exponent e
            n: modulus n

        Returns:
            Tuple of (PrivateKey, None) on success or (None, None) on failure
        """
        from RsaCtfTool.lib.keys_wrapper import PrivateKey

        if primes and len(primes) >= 2:
            try:
                priv_key = PrivateKey(primes=primes, e=int(e), n=int(n))
                if priv_key.key is None and priv_key.d is None:
                    return None, None
                return priv_key, None
            except (ValueError, TypeError):
                return None, None
        return None, None
