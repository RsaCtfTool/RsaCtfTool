#!/usr/bin/env python3

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from RsaCtfTool.lib.exceptions import FactorizationError


class TestFactorizationError:
    def test_factorization_error_can_be_raised(self):
        with pytest.raises(FactorizationError):
            raise FactorizationError("Test error")

    def test_factorization_error_message(self):
        msg = "Factorization failed"
        try:
            raise FactorizationError(msg)
        except FactorizationError as e:
            assert str(e) == msg

    def test_factorization_error_inheritance(self):
        assert issubclass(FactorizationError, Exception)
