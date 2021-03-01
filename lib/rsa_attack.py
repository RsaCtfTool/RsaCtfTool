#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import importlib
from glob import glob
from lib.keys_wrapper import PublicKey
from lib.exceptions import FactorizationError
from lib.utils import sageworks, print_results
from lib.fdb import send2fdb
from Crypto.Util.number import bytes_to_long, long_to_bytes
from attacks.multi_keys import same_n_huge_e, commonfactors


class RSAAttack(object):
    def __init__(self, args):
        """Main class managing the attacks"""
        self.args = args
        self.logger = logging.getLogger("global_logger")

        # Load ciphertext
        if args.uncipher is not None:
            self.cipher = args.uncipher
        else:
            self.cipher = None

        self.priv_key = None
        self.priv_keys = []
        self.partitial_priv_key = None
        self.unciphered = []
        self.implemented_attacks = []

    def get_boolean_results(self):
        """Return a boolean value according to requested
        actions (private, uncipher) if actions are done or not
        """
        if self.args.private and self.priv_key:
            return True

        if self.args.uncipher and self.unciphered:
            return True

        return False

    def can_stop_tests(self):
        """Return a boolean if requested actions are done
        avoiding running extra attacks
        """
        if self.args.private is not None and self.priv_key is not None:
            if self.args.uncipher is None:
                return True
            if self.args.uncipher is not None and self.unciphered is not []:
                return True

        if self.args.uncipher is not None and self.unciphered is not []:
            if self.args.private is None:
                return True
            if self.args.private is not None and self.priv_key is not None:
                return True

        return False

    def print_results_details(self, publickeyname):
        """Print extra output according to requested action.
        Uncipher data if needed.
        """
        # check and print resulting private key
        if self.partitial_priv_key is not None and self.args.private:
            self.logger.info("d: %i" % self.partitial_priv_key.key.d)
            self.logger.info("e: %i" % self.partitial_priv_key.key.e)
            self.logger.info("n: %i" % self.partitial_priv_key.key.n)

        # If we wanted to decrypt, do it now
        if self.cipher and self.priv_key is not None:
            for cipher in self.cipher:
                unciphered = self.priv_key.decrypt(cipher)
                if not isinstance(unciphered, list):
                    unciphered = [unciphered]

                self.unciphered = self.unciphered + unciphered
        elif self.cipher and self.partitial_priv_key is not None:
            # needed, if n is prime and so we cant calc p and q
            enc_msg = bytes_to_long(self.cipher)
            dec_msg = self.partitial_priv_key.key._decrypt(enc_msg)
            self.unciphered.append(long_to_bytes(dec_msg))

        print_results(self.args, publickeyname, self.priv_key, self.unciphered)

    def load_attacks(self, attacks_list, multikeys=False):
        """Dynamic load attacks according to context (single key or multiple keys)"""
        try:
            attacks_list.remove("all")
        except ValueError:
            pass

        try:
            attacks_list.remove("nullattack")
        except ValueError:
            pass

        for attack in attacks_list:
            if attack == self.args.attack or self.args.attack == "all":
                try:
                    if multikeys:
                        attack_module = importlib.import_module(
                            "attacks.multi_keys.%s" % attack
                        )
                    else:
                        attack_module = importlib.import_module(
                            "attacks.single_key.%s" % attack
                        )
                    try:
                        if attack_module.__SAGE__:
                            if not sageworks():
                                self.logger.warning(
                                    "Can't load %s because sage is not installed"
                                    % attack
                                )
                                continue
                    except:
                        pass
                    self.implemented_attacks.append(attack_module)
                except ModuleNotFoundError:
                    pass

    def attack_multiple_keys(self, publickeys, attacks_list):
        """Run attacks on multiple keys"""
        self.logger.info("[*] Multikey mode using keys: " + ", ".join(publickeys))
        self.load_attacks(attacks_list, multikeys=True)

        # Read keyfiles
        publickeys_obj = []
        for publickey in publickeys:
            try:
                with open(publickey, "rb") as pubkey_fd:
                    publickeys_obj.append(PublicKey(pubkey_fd.read(), publickey))
            except Exception:
                print("Key format not supported : %s." % publickey)
                pass

        if len(publickeys_obj) == 0:
            self.logger.error("No key loaded.")
            exit(1)

        self.publickey = publickeys_obj
        # Loop through implemented attack methods and conduct attacks
        for attack_module in self.implemented_attacks:
            if isinstance(self.publickey, list):
                self.logger.info(
                    "[*] Performing %s attack." % attack_module.__name__.split(".")[-1]
                )
                try:
                    self.priv_key, unciphered = attack_module.attack(
                        self, self.publickey, self.cipher
                    )
                    if unciphered is not None and unciphered is not []:
                        if isinstance(unciphered, list):
                            self.unciphered = self.unciphered + unciphered
                        else:
                            self.unciphered.append(unciphered)
                    if self.can_stop_tests():
                        break
                except FactorizationError:
                    self.logger.warning("Timeout")

        public_key_name = ",".join(publickeys)
        self.print_results_details(public_key_name)
        if self.args.sendtofdb == True:
            if len(self.priv_key) > 0:
                for privkey in list(set(self.priv_key)):
                    send2fdb(privkey.n, [privkey.p, privkey.q])
        return self.get_boolean_results()

    def attack_single_key(self, publickey, attacks_list=[]):
        """Run attacks on single keys"""

        if len(attacks_list) == 0:
            self.args.attack = "all"

        self.load_attacks(attacks_list)

        # Read keyfile
        with open(publickey, "rb") as pubkey_fd:
            self.publickey = PublicKey(pubkey_fd.read(), publickey)

        # Read n/e from publickey file
        if not self.args.n or not self.args.e:
            self.args.n = self.publickey.n
            self.args.e = self.publickey.e

        # Loop through implemented attack methods and conduct attacks
        for attack_module in self.implemented_attacks:
            self.logger.info(
                "[*] Performing %s attack on %s."
                % (attack_module.__name__.split(".")[-1], self.publickey.filename)
            )
            try:
                self.priv_key, unciphered = attack_module.attack(
                    self, self.publickey, self.cipher
                )
                if unciphered is not None and unciphered is not []:
                    if isinstance(unciphered, list):
                        self.unciphered = self.unciphered + unciphered
                    else:
                        self.unciphered.append(unciphered)
                if self.can_stop_tests():
                    break
            except FactorizationError:
                self.logger.warning("Timeout")

        self.print_results_details(publickey)
        if self.args.sendtofdb == True:
            if self.priv_key != None:
                send2fdb(self.priv_key.n, [self.priv_key.p, self.priv_key.q])
        return self.get_boolean_results()
