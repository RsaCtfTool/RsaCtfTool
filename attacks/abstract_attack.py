#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from pathlib import Path
import sys
from lib.utils import sageworks


class AbstractAttack(object):
    speed_enum = {"slow": 0, "medium": 1, "fast": 2}

    def __init__(self, attack_rsa_obj, timeout=60):
        self.logger = logging.getLogger("global_logger")
        self.speed = AbstractAttack.speed_enum["medium"]
        self.sage_required = False
        self.timeout = timeout
        self.attack_rsa_obj = attack_rsa_obj

    def get_name(self):
        """Return attack name"""
        full_path = sys.modules[self.__class__.__module__].__file__
        return Path(full_path).name.split(".")[0]

    def can_run(self):
        """Test if everything is ok for running attack"""
        if self.sage_required:
            if not sageworks():
                self.logger.warning(
                    "Can't load %s because sage is not installed" % attack
                )
                return False
        return True

    def attack(self, publickeys, cipher=[]):
        """Attack implementation"""
        raise NotImplementedError

    def test(self):
        """Attack test case"""
        raise NotImplementedError