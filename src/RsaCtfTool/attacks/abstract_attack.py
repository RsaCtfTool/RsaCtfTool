#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from pathlib import Path
import sys
from typing import List, Any, Optional, Tuple
import shutil
from RsaCtfTool.lib.utils import timeout


class AbstractAttack(object):
    speed_enum = {"slow": 0, "medium": 1, "fast": 2}

    def __init__(self, timeout: int = 60):
        self.logger = logging.getLogger("global_logger")
        self.speed = AbstractAttack.speed_enum["medium"]
        self.timeout = timeout
        self.required_binaries = []

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
        return True

    def attack(self, publickeys: List[Any], cipher: Optional[List[Any]] = None, progress: bool = True) -> Tuple[Optional[Any], Optional[Any]]:
        """Attack implementation"""
        if cipher is None:
            cipher = []
        raise NotImplementedError

    def attack_wrapper(self, publickeys: List[Any], cipher: Optional[List[Any]] = None, progress: bool = True) -> Tuple[Optional[Any], Optional[Any]]:
        """Attack wrapper to include timer in all attacks"""
        with timeout(self.timeout):
            try:
                return self.attack(publickeys, cipher, progress)
            except TimeoutError:
                return None, None

    def test(self) -> None:
        """Attack test case"""
        raise NotImplementedError

    def create_private_key(self, publickey) -> Tuple[Optional[Any], Optional[Any]]:
        """Helper method to create a private key from publickey with p and q
        
        Args:
            publickey: PublicKey object with n, e, p, q attributes
            
        Returns:
            Tuple of (PrivateKey, None) on success or (None, None) on failure
        """
        from RsaCtfTool.lib.keys_wrapper import PrivateKey
        
        if publickey.p is not None and publickey.q is not None:
            try:
                priv_key = PrivateKey(
                    n=publickey.n,
                    p=int(publickey.p),
                    q=int(publickey.q),
                    e=int(publickey.e),
                )
                return priv_key, None
            except ValueError:
                return None, None
        return None, None

    def create_private_key_from_pqe(self, p, q, e, n) -> Tuple[Optional[Any], Optional[Any]]:
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
                return priv_key, None
            except (ValueError, TypeError):
                return None, None
        return None, None


# Configure logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
