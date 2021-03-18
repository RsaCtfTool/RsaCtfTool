#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack


class Attack(AbstractAttack):
    def __init__(self, attack_rsa_obj, timeout=60):
        super().__init__(attack_rsa_obj, timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[]):
        """Do nothing, used for multi-key attacks that succeeded so we just print the
        private key without spending any time factoring
        """
        return (None, None)

    def test(self):
        """Nothing to test"""
        pass
