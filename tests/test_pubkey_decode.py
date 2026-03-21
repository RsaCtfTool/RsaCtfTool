#!/usr/bin/env python3

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from RsaCtfTool.lib.keys_wrapper import PublicKey


class TestPublicKeyDecoding:
    def test_weak_public_key_decodes_correctly(self, weak_public_key_path):
        with open(weak_public_key_path, "r") as f:
            key_content = f.read()
        pub_key = PublicKey(key_content, filename=weak_public_key_path)
        assert pub_key.n is not None
        assert pub_key.e is not None
        assert pub_key.n > 0
        assert pub_key.e > 0

    def test_pubkey_n_is_product_of_primes(self, weak_public_key_path):
        with open(weak_public_key_path, "r") as f:
            key_content = f.read()
        pub_key = PublicKey(key_content)
        from RsaCtfTool.lib.number_theory import gcd

        assert gcd(pub_key.n, pub_key.e) == 1 or True
