#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import logging
import importlib
from lib.keys_wrapper import PublicKey, PrivateKey
from lib.exceptions import FactorizationError
from lib.utils import print_results
from lib.fdb import send2fdb
from lib.crypto_wrapper import bytes_to_long, long_to_bytes
import inspect
from lib.number_theory import is_prime, isqrt, gcd
import traceback


class RSAAttack(object):
    def __init__(self, args):
        """Main class managing the attacks"""
        self.args = args
        self.logger = logging.getLogger("global_logger")

        # Load ciphertext
        self.cipher = args.decrypt if args.decrypt is not None else None
        self.priv_key = None
        self.priv_keys = []
        self.partitial_priv_key = None
        self.decrypted = []
        self.implemented_attacks = []

    def get_boolean_results(self):
        """Return a boolean value according to requested
        actions (private, decrypt) if actions are done or not
        """
        if self.args.private and self.priv_key:
            return True

        return bool(self.args.decrypt and self.decrypted)

    def can_stop_tests(self):
        """Return a boolean if requested actions are done
        avoiding running extra attacks
        """
        if self.args.private is not None and self.priv_key is not None:
            if self.args.decrypt is None:
                return True
            if self.decrypted is not []:
                return True

        if self.args.decrypt is not None and self.decrypted is not []:
            if self.args.private is None:
                return True
            if self.priv_key is not None:
                return True

        return False

    def print_results_details(self, publickeyname):
        """Print extra output according to requested action.
        Decrypt data if needed.
        """
        # check and print resulting private key
        if self.partitial_priv_key is not None and self.args.private:
            self.logger.info("d: %i" % self.partitial_priv_key.key.d)
            self.logger.info("e: %i" % self.partitial_priv_key.key.e)
            self.logger.info("n: %i" % self.partitial_priv_key.key.n)

        # If we wanted to decrypt, do it now
        if self.cipher:
            if self.priv_key is not None:
                for cipher in self.cipher:
                    priv_keys = (
                        [self.priv_key]
                        if not isinstance(self.priv_key, list)
                        else self.priv_key
                    )
                    if self.args.check_publickey:
                        k, ok = self.pre_attack_check(priv_keys)
                        if not ok:
                            return False

                    for priv_key in priv_keys:
                        decrypted = priv_key.decrypt(cipher)
                        if not isinstance(decrypted, list):
                            decrypted = [decrypted]

                    self.decrypted = self.decrypted + decrypted
            elif self.partitial_priv_key is not None:
                # needed, if n is prime and so we cant calc p and q
                enc_msg = bytes_to_long(self.cipher)
                dec_msg = self.partitial_priv_key.key._decrypt(enc_msg)
                self.decrypted.append(long_to_bytes(dec_msg))

        print_results(self.args, publickeyname, self.priv_key, self.decrypted)

    def pre_attack_check(self, publickeys):
        """Basic pre Attack checks implementation"""
        if not isinstance(publickeys, list):
            publickeys = [publickeys]
        tmp = []
        ok = True
        for publickey in publickeys:
            if publickey.n & 1 == 0:
                self.logger.error(
                    f"[!] Public key: {publickey.filename} modulus should be odd."
                )
                ok = False
            if gcd(publickey.n, publickey.e) > 1:
                self.logger.error(
                    f"[!] Public key: {publickey.filename} modulus is coprime with exponent."
                )
                ok = False
            if publickey.n <= 3:
                self.logger.error(
                    f"[!] Public key: {publickey.filename} modulus should be > 3."
                )
                ok = False
            if is_prime(publickey.n):
                self.logger.error(
                    f"[!] Public key: {publickey.filename} modulus should not be prime."
                )
                ok = False
            i = isqrt(publickey.n)
            if publickey.n == (i**2):
                self.logger.error(
                    f"[!] Public key: {publickey.filename} modulus should not be a perfect square."
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
                        attack_module = importlib.import_module(f"attacks.multi_keys.{attack}")
                    else:
                        attack_module = importlib.import_module(f"attacks.single_key.{attack}")

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
        if self.args.sendtofdb:
            if self.priv_key is not None:
                if type(self.priv_key) is PrivateKey:
                    send2fdb(self.priv_key.n, [self.priv_key.p, self.priv_key.q])
                elif len(self.priv_key) > 0:
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
                    publickeys_obj.append(
                        PublicKey(pubkey_fd.read(), filename=publickey)
                    )
            except Exception:
                self.logger.error(f"[*] Key format not supported : {publickey}.")
                continue

        if not publickeys_obj:
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
                self.logger.info(f"[*] Performing {attack_module.get_name()} attack.")
                try:
                    if not attack_module.can_run():
                        continue

                    self.priv_key, decrypted = attack_module.attack(
                        self.publickey, self.cipher
                    )

                    if decrypted is not None and decrypted is not []:
                        if isinstance(decrypted, list):
                            self.decrypted = self.decrypted + decrypted
                        else:
                            self.decrypted.append(decrypted)
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

        l = len(attacks_list)
        if l == 0:
            self.args.attack = "all"

        self.load_attacks(attacks_list)
        T = []
        if test:
            self.load_attacks(attacks_list, multikeys=True)
            for c, attack in enumerate(self.implemented_attacks, start=1):
                t0 = time.time()
                if attack.can_run():
                    self.logger.info(
                        "[*] %d of %d, Testing: %s" % (c, l, attack.get_name())
                    )
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
                t1 = time.time()
                td = t1 - t0
                T += [td]
                self.logger.info("[+] Time elapsed: %.4f sec." % round(td, 4))
            if len(T) > 0:
                tmin, tmax, tavg = min(T), max(T), sum(T) / len(T)
                self.logger.info(
                    "[+] Total time elapsed min,max,avg: %.4f/%.4f/%.4f sec."
                    % (round(tmin, 4), round(tmax, 4), round(tavg, 4))
                )
            return

        if isinstance(publickey, str):
            # Read keyfile
            try:
                with open(publickey, "rb") as pubkey_fd:
                    self.publickey = PublicKey(pubkey_fd.read(), filename=publickey)
            except Exception as e:
                self.logger.error(f"[!] {e}.")
                return
            if self.args.check_publickey:
                k, ok = self.pre_attack_check(self.publickey)
                if not ok:
                    return False
            # Read n/e from publickey file
            if not self.args.n or not self.args.e:
                self.args.n = self.publickey.n
                self.args.e = self.publickey.e
        else:
            self.publickey = publickey

        if is_prime(self.publickey.n):
            self.logger.warning(
                "[!] Your provided modulus is prime:\n%d\nThere is no need to run an integer factorization..."
                % self.publickey.n
            )
            return True

        if self.args.p is not None and self.args.q is None:
            self.args.q = self.args.n // self.args.p

        if self.args.q is not None and self.args.p is None:
            self.args.p = self.args.n // self.args.q

        self.need_run = self.args.p is None or self.args.q is None

        if self.args.show_modulus is not None and self.args.show_modulus == True:
            print("modulus:", self.args.n)

        T = []
        # Loop through implemented attack methods and conduct attacks
        for attack_module in self.implemented_attacks:
            t0 = time.time()
            if self.need_run:
                self.logger.info(
                    f"[*] Performing {attack_module.get_name()} attack on {self.publickey.filename}."
                )
            try:
                if not attack_module.can_run():
                    continue

                if self.need_run:
                    self.priv_key, decrypted = attack_module.attack_wrapper(
                        self.publickey, self.cipher
                    )
                else:
                    self.logger.warning(
                        "[!] No need to factorize since you provided a prime factor..."
                    )
                    decrypted = None
                    self.priv_key = priv_key = PrivateKey(
                        self.args.p, self.args.q, self.args.e, self.args.n
                    )

                if decrypted is not None and decrypted is not []:
                    if isinstance(decrypted, list):
                        self.decrypted = self.decrypted + decrypted
                    else:
                        self.decrypted.append(decrypted)
                if self.can_stop_tests():
                    if self.need_run:
                        self.logger.info(
                            f"[*] Attack success with {attack_module.get_name()} method !"
                        )
                    break
            except TimeoutError:
                self.logger.warning("Timeout")
            except FactorizationError:
                self.logger.warning("FactorizationError")
            except NotImplementedError:
                self.logger.warning("[!] This attack module is not implemented yet")
            except KeyboardInterrupt:
                self.logger.warning("[!] Interrupted")
            except Exception as e:
                if self.args.withtraceback:
                    self.logger.error(
                        "[!] An exception has occurred during the attack. Please check your inputs."
                    )
                    self.logger.error(f"[!] {e}")
                    self.logger.error(f"[!] {traceback.format_exc()}")
            t1 = time.time()
            td = t1 - t0
            T += [td]
            self.logger.info("[+] Time elapsed: %.4f sec." % round(td, 4))
        if len(T) > 0:
            tmin, tmax, tavg = min(T), max(T), sum(T) / len(T)
            self.logger.info(
                "[+] Total time elapsed min,max,avg: %.4f/%.4f/%.4f sec."
                % (round(tmin, 4), round(tmax, 4), round(tavg, 4))
            )
        self.print_results_details(publickey)
        self.priv_key_send2fdb()
        return self.get_boolean_results()
