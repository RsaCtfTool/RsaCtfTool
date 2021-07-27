#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import importlib
from lib.keys_wrapper import PublicKey, PrivateKey
from lib.exceptions import FactorizationError
from lib.utils import print_results
from lib.fdb import send2fdb
from Crypto.Util.number import bytes_to_long, long_to_bytes
import inspect
from lib.rsalibnum import is_prime, isqrt, gcd


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
                if not isinstance(self.priv_key, list):
                    priv_keys = [self.priv_key]
                else:
                    priv_keys = self.priv_key

                if self.args.check_publickey:
                    k, ok = self.pre_attack_check(priv_keys)
                    if not ok:
                        return False

                for priv_key in priv_keys:
                    unciphered = priv_key.decrypt(cipher)
                    if not isinstance(unciphered, list):
                        unciphered = [unciphered]

                self.unciphered = self.unciphered + unciphered
        elif self.cipher and self.partitial_priv_key is not None:
            # needed, if n is prime and so we cant calc p and q
            enc_msg = bytes_to_long(self.cipher)
            dec_msg = self.partitial_priv_key.key._decrypt(enc_msg)
            self.unciphered.append(long_to_bytes(dec_msg))

        print_results(self.args, publickeyname, self.priv_key, self.unciphered)

    def pre_attack_check(self, publickeys):
        """Basic pre Attack checks implementation"""
        if not isinstance(publickeys, list):
            publickeys = [publickeys]
        tmp = []
        ok = True
        for publickey in publickeys:
            if publickey.n & 1 == 0:
                self.logger.error(
                    "[!] Public key: %s modulus should be odd." % publickey.filename
                )
                ok = False
            if gcd(publickey.n, publickey.e) > 1:
                self.logger.error(
                    "[!] Public key: %s modulus is coprime with exponent."
                    % publickey.filename
                )
                ok = False
            if not (publickey.n > 3):
                self.logger.error(
                    "[!] Public key: %s modulus should be > 3." % publickey.filename
                )
                ok = False
            if is_prime(publickey.n):
                self.logger.error(
                    "[!] Public key: %s modulus should not be prime."
                    % publickey.filename
                )
                ok = False
            i = isqrt(publickey.n)
            if publickey.n == (i ** 2):
                self.logger.error(
                    "[!] Public key: %s modulus should not be a perfect square."
                    % publickey.filename
                )
                publickey.p = i
                publickey.q = i
                tmp.append(publickey)
                ok = False
        return (tmp, ok)

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
            if attack in self.args.attack or "all" in self.args.attack:
                try:
                    if multikeys:
                        attack_module = importlib.import_module(
                            "attacks.multi_keys.%s" % attack
                        )
                    else:
                        attack_module = importlib.import_module(
                            "attacks.single_key.%s" % attack
                        )

                    # Dynamically add named-arguments to constructor if same sys.argv exists
                    expected_args = list(
                        inspect.getfullargspec(attack_module.Attack.__init__).args
                    )
                    expected_args.remove("self")

                    constructor_args = {}
                    for arg in vars(self.args):
                        key = arg
                        value = getattr(self.args, arg)
                        if key in expected_args:
                            constructor_args[key] = value

                    # Retrocompatibility
                    if "attack_rsa_obj" in expected_args:
                        constructor_args["attack_rsa_obj"] = self

                    # Add attack instance to attack list
                    self.implemented_attacks.append(
                        attack_module.Attack(**constructor_args)
                    )
                except ModuleNotFoundError:
                    pass
        self.implemented_attacks.sort(key=lambda x: x.speed, reverse=True)

    def priv_key_send2fdb(self):
        if self.args.sendtofdb == True:
            if self.priv_key is not None:
                if type(self.priv_key) is PrivateKey:
                    send2fdb(self.priv_key.n, [self.priv_key.p, self.priv_key.q])
                else:
                    if len(self.priv_key) > 0:
                        for privkey in list(set(self.priv_key)):
                            send2fdb(privkey.n, [privkey.p, privkey.q])

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
                self.logger.error("[*] Key format not supported : %s." % publickey)
                continue

        if len(publickeys_obj) == 0:
            self.logger.error("No key loaded.")
            exit(1)

        self.publickey = publickeys_obj
        if self.args.check_publickey:
            k, ok = self.pre_attack_check(self.publickey)
            if not ok:
                return False
        # Loop through implemented attack methods and conduct attacks
        for attack_module in self.implemented_attacks:
            if isinstance(self.publickey, list):
                self.logger.info("[*] Performing %s attack." % attack_module.get_name())
                try:
                    if not attack_module.can_run():
                        continue

                    self.priv_key, unciphered = attack_module.attack(
                        self.publickey, self.cipher
                    )

                    if unciphered is not None and unciphered is not []:
                        if isinstance(unciphered, list):
                            self.unciphered = self.unciphered + unciphered
                        else:
                            self.unciphered.append(unciphered)
                    if self.can_stop_tests():
                        self.logger.info(
                            f"[*] Attack success with {attack_module.get_name()} method !"
                        )
                        break
                except FactorizationError:
                    self.logger.warning("Timeout")

        public_key_name = ",".join(publickeys)
        self.print_results_details(public_key_name)
        self.priv_key_send2fdb()
        return self.get_boolean_results()

    def attack_single_key(self, publickey, attacks_list=[], test=False):
        """Run attacks on single keys"""

        if len(attacks_list) == 0:
            self.args.attack = "all"

        self.load_attacks(attacks_list)
        if test:
            for attack in self.implemented_attacks:
                if attack.can_run():
                    self.logger.info("[*] Testing %s" % attack.get_name())
                    try:
                        try:
                            if attack.test():
                                self.logger.info("[*] Success")
                            else:
                                self.logger.error("[!] Failure")
                        except NotImplementedError:
                            self.logger.warning("[!] Test not implemented")
                    except Exception:
                        self.logger.error("[!] Failure")
            exit(0)

        # Read keyfile
        try:
            with open(publickey, "rb") as pubkey_fd:
                self.publickey = PublicKey(pubkey_fd.read(), publickey)
        except Exception as e:
            self.logger.error("[*] %s." % e)
            return

        if self.args.check_publickey:
            k, ok = self.pre_attack_check(self.publickey)
            if not ok:
                return False
        # Read n/e from publickey file
        if not self.args.n or not self.args.e:
            self.args.n = self.publickey.n
            self.args.e = self.publickey.e

        # Loop through implemented attack methods and conduct attacks
        for attack_module in self.implemented_attacks:
            self.logger.info(
                "[*] Performing %s attack on %s."
                % (attack_module.get_name(), self.publickey.filename)
            )
            try:
                if not attack_module.can_run():
                    continue

                self.priv_key, unciphered = attack_module.attack(
                    self.publickey, self.cipher
                )
                if unciphered is not None and unciphered is not []:
                    if isinstance(unciphered, list):
                        self.unciphered = self.unciphered + unciphered
                    else:
                        self.unciphered.append(unciphered)
                if self.can_stop_tests():
                    self.logger.info(
                        f"[*] Attack success with {attack_module.get_name()} method !"
                    )
                    break
            except FactorizationError:
                self.logger.warning("Timeout")
            except NotImplementedError:
                self.logger.warning("[!] This attack module is not implemented yet")

        self.print_results_details(publickey)
        self.priv_key_send2fdb()
        return self.get_boolean_results()
