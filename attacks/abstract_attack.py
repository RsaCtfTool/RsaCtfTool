#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import sys
import shutil
from lib.utils import sageworks, timeout, TimeoutError
from pathlib import Path



class AbstractAttack(object):
    speed_enum = {"slow": 0, "medium": 1, "fast": 2}

    def __init__(self, timeout=60):
        self.logger = logging.getLogger("global_logger")
        self.speed = AbstractAttack.speed_enum["medium"]
        self.timeout = timeout
        self.required_binaries = []

    def get_name(self):
        """Return attack name"""
        full_path = sys.modules[self.__class__.__module__].__file__
        return Path(full_path).name.split(".")[0]

    def can_run(self):
        """Test if everything is ok for running attack"""
        for required_binary in self.required_binaries:
            if shutil.which(required_binary) is None:
                self.logger.warning(
                    "Can't load %s because %s binary is not installed"
                    % (self.get_name(), required_binary)
                )
                return False
        return True
        
        
    def attack(self, publickeys, cipher=[], progress=True):
        """Attack implementation"""
        raise NotImplementedError
        
    def _attack(self, publickeys, cipher=[], progress=True):
        """Attack wrapper to include timer in all attacks"""
        with timeout(self.timeout):
            try:
                return self.attack(publickeys, cipher)
            except TimeoutError:
                return(None, None)

    def test(self):
        """Attack test case"""
        raise NotImplementedError
