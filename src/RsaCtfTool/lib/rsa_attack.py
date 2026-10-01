#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import logging
import importlib
import inspect
import sys
import traceback
from RsaCtfTool.lib.keys_wrapper import PublicKey, PrivateKey
from RsaCtfTool.lib.exceptions import FactorizationError
from RsaCtfTool.lib.utils import print_results, timeout, TimeoutError
from RsaCtfTool.lib.fdb import send2fdb
from RsaCtfTool.lib.number_theory import is_prime, isqrt, gcd


class RSAAttack(object):
    def __init__(self, args):
        """Main class managing the attacks"""
        self.args = args
        self.logger = logging.getLogger("global_logger")

        # Load ciphertext
        self.cipher = args.decrypt if args.decrypt is not None else None
        self.priv_key = None
        self.priv_keys = []
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
        # A recovered private key is sufficient to stop attacking.  Ciphertext
        # decryption happens in print_results_details() after the attack loop.
        if self.priv_key is not None:
            return True

        # Some attacks recover plaintext directly without recovering a key.
        return bool(self.decrypted and not self.args.private)

    def print_results_details(self, publickeyname):
        """Print extra output according to requested action.
        Decrypt data if needed.
        """
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
                    f"[!] Public key: {publickey.filename} modulus is NOT coprime with exponent."
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
                # Not a failure: p = q = isqrt(n) are the factors, and
                # attacks such as nonRSA handle prime powers directly.
                self.logger.warning(
                    f"[!] Public key: {publickey.filename} modulus is a perfect square; p = q = isqrt(n)."
                )
                publickey.p = i
                publickey.q = i
                tmp.append(publickey)
        return (tmp, ok)

    def get_attack(self, attack, multikeys):
        if multikeys:
            import_path = f"RsaCtfTool.attacks.multi_keys.{attack}"
        else:
            import_path = f"RsaCtfTool.attacks.single_key.{attack}"
        return importlib.import_module(import_path, package="RsaCtfTool")

    def load_attacks(self, attacks_list, multikeys=False):
        """Dynamic load attacks according to context (single key or multiple keys)"""
        # Work on a copy: the caller's list is usually args.attacks_list,
        # which later phases (test mode, multi-key mode) still need intact.
        attacks_list = [a for a in attacks_list if a not in ("all", "nullattack")]

        for attack in attacks_list:
            if attack in self.args.attack or "all" in self.args.attack:
                try:
                    attack_module = self.get_attack(attack, multikeys)
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
                except ModuleNotFoundError as exc:
                    # attacks_list mixes single_key and multi_keys names, so
                    # names absent from *this* package are expected; a module
                    # that exists but fails on its own third-party imports
                    # (e.g. missing z3) must not vanish silently.
                    if exc.name is None or not exc.name.startswith("RsaCtfTool."):
                        self.logger.debug(f"[-] Attack {attack} unavailable: {exc}")
        self.implemented_attacks.sort(key=lambda x: x.speed, reverse=True)

    def priv_key_send2fdb(self):
        if self.args.sendtofdb:
            if self.priv_key is not None:
                if type(self.priv_key) is PrivateKey:
                    # Keys without recovered factors (e.g. d-only keys from
                    # nonRSA) would report "None" factors to the database.
                    if self.priv_key.p is not None and self.priv_key.q is not None:
                        send2fdb(self.priv_key.n, [self.priv_key.p, self.priv_key.q])
                elif len(self.priv_key) > 0:
                    for privkey in list(set(self.priv_key)):
                        if privkey.p is not None and privkey.q is not None:
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
            sys.exit(1)

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

                    # Same timeout wrapper and error hygiene the single-key
                    # loop gets; previously a plain exception in any
                    # multi-key attack aborted the whole run.
                    with timeout(attack_module.timeout):
                        self.priv_key, decrypted = attack_module.attack(
                            self.publickey, self.cipher
                        )

                    if self.priv_key is not None and not isinstance(
                        self.priv_key, list
                    ):
                        self._reject_unusable_priv_key()

                    if decrypted is not None and decrypted != []:
                        if isinstance(decrypted, list):
                            self.decrypted = self.decrypted + decrypted
                        else:
                            self.decrypted.append(decrypted)
                    if self.can_stop_tests():
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
                    self.logger.error(
                        "[!] An exception has occurred during the attack. Please check your inputs."
                    )
                    self.logger.error(
                        f"[!] {attack_module.get_name()}: {type(e).__name__}: {e}"
                    )

        public_key_name = ",".join(publickeys)
        self.print_results_details(public_key_name)
        self.priv_key_send2fdb()
        return self.get_boolean_results()

    def _attack_test_mode(self, attacks_list):
        num_attacks = len(attacks_list)
        self.load_attacks(attacks_list, multikeys=True)
        T = []
        for c, attack in enumerate(self.implemented_attacks, start=1):
            t0 = time.time()
            if attack.can_run():
                self.logger.info(
                    "[*] %d of %d, Testing: %s"
                    % (c, num_attacks, attack.get_name())
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

    def _load_public_key(self, publickey):
        if isinstance(publickey, str):
            try:
                with open(publickey, "rb") as pubkey_fd:
                    self.publickey = PublicKey(pubkey_fd.read(), filename=publickey)
            except Exception as e:
                self.logger.error(f"[!] {e}.")
                return False
            if self.args.check_publickey:
                k, ok = self.pre_attack_check(self.publickey)
                if not ok:
                    return False
            if not self.args.n or not self.args.e:
                self.args.n = self.publickey.n
                self.args.e = self.publickey.e
        else:
            self.publickey = publickey
        return True

    def _handle_provided_primes(self):
        # A supplied prime that does not divide n would floor-divide into a
        # wrong partner and then construct an unusable key that still stops
        # the attack loop - reject it instead of trusting it.
        if self.args.p is not None and self.args.q is None:
            if self.args.n is not None and self.args.n % self.args.p == 0:
                self.args.q = self.args.n // self.args.p
            else:
                self.logger.error("[!] Provided p does not divide n; ignoring it.")
                self.args.p = None
        if self.args.q is not None and self.args.p is None:
            if self.args.n is not None and self.args.n % self.args.q == 0:
                self.args.p = self.args.n // self.args.q
            else:
                self.logger.error("[!] Provided q does not divide n; ignoring it.")
                self.args.q = None
        if (
            self.args.p is not None
            and self.args.q is not None
            and self.args.n is not None
            and self.args.p * self.args.q != self.args.n
        ):
            if hasattr(self.args, "primes") and self.args.primes:
                pass
            elif self.args.n % self.args.p == 0 and self.args.n % self.args.q == 0:
                self.logger.info("[*] Multiple prime factors provided for multi-prime modulus.")
            else:
                self.logger.error(
                    "[!] Provided p and q do not multiply to n; ignoring them."
                )
                self.args.p = None
                self.args.q = None
        self.need_run = (self.args.p is None or self.args.q is None) and (
            not getattr(self.args, "primes", None)
        )
        if self.args.show_modulus:
            self.logger.info("modulus: %s", self.args.n)

    def _reject_unusable_priv_key(self):
        """Drop a recovered key that carries neither a constructed key
        object nor a bare private exponent - an empty shell that would
        otherwise be reported as a success and stop the attack loop.
        """
        if self.priv_key is None:
            return
        if (
            getattr(self.priv_key, "d", None) is None
            and getattr(self.priv_key, "key", None) is None
        ):
            self.priv_key = None

    def _execute_single_attack(self, attack_module):
        if not attack_module.can_run():
            return False
        if self.need_run:
            self.priv_key, decrypted = attack_module.attack_wrapper(
                self.publickey, self.cipher
            )
            self._reject_unusable_priv_key()
        else:
            self.logger.warning(
                "[!] No need to factorize since you provided prime factor(s)..."
            )
            decrypted = None
            if getattr(self.args, "primes", None):
                self.priv_key = PrivateKey(
                    primes=self.args.primes, e=self.args.e, n=self.args.n
                )
            else:
                self.priv_key = PrivateKey(
                    self.args.p, self.args.q, self.args.e, self.args.n
                )
            # e sharing a factor with phi yields an inert shell key; report
            # failure instead of "success" with an unusable key.
            self._reject_unusable_priv_key()
        if decrypted is not None and decrypted != []:
            if isinstance(decrypted, list):
                self.decrypted = self.decrypted + decrypted
            else:
                self.decrypted.append(decrypted)
        if self.can_stop_tests():
            if self.need_run:
                self.logger.info(
                    f"[*] Attack success with {attack_module.get_name()} method !"
                )
            return True
        return False

    def _run_attack_loop(self, publickey):
        T = []
        for attack_module in self.implemented_attacks:
            t0 = time.time()
            if self.need_run:
                self.logger.info(
                    f"[*] Performing {attack_module.get_name()} attack on {self.publickey.filename}."
                )
            try:
                if self._execute_single_attack(attack_module):
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
                self.logger.error(
                    "[!] An exception has occurred during the attack. Please check your inputs."
                )
                self.logger.error(
                    f"[!] {attack_module.get_name()}: {type(e).__name__}: {e}"
                )
                if self.args.withtraceback:
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

    def attack_single_key(self, publickey, attacks_list=None, test=False):
        """Run attacks on single keys"""
        if attacks_list is None:
            attacks_list = []
        num_attacks = len(attacks_list)
        if num_attacks == 0:
            self.args.attack = "all"

        self.load_attacks(attacks_list)
        if test:
            self._attack_test_mode(attacks_list)
            return

        if not self._load_public_key(publickey):
            return

        # Degenerate moduli only produce noisy crashes inside the attacks;
        # there is never anything to factor below 4.
        if self.publickey.n is None or self.publickey.n < 4:
            self.logger.warning(
                "[!] Your provided modulus is too small to factor: %s"
                % self.publickey.n
            )
            return True

        if is_prime(self.publickey.n):
            self.logger.warning(
                "[!] Your provided modulus is prime:\n%d\nThere is no need to run an integer factorization..."
                % self.publickey.n
            )
            return True

        self._handle_provided_primes()
        self._run_attack_loop(publickey)
        self.print_results_details(publickey)
        self.priv_key_send2fdb()
        return self.get_boolean_results()
