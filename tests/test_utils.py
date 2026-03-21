#!/usr/bin/env python3

from RsaCtfTool.lib.utils import (
    get_numeric_value,
    get_base64_value,
    s2n,
    n2s,
    binary_search,
)


class TestGetNumericValue:
    def test_hex_value(self):
        assert get_numeric_value("0x10") == 16
        assert get_numeric_value("0xff") == 255

    def test_decimal_value(self):
        assert get_numeric_value("100") == 100
        assert get_numeric_value("12345") == 12345

    def test_large_numbers(self):
        assert get_numeric_value("123456789") == 123456789


class TestGetBase64Value:
    def test_valid_base64(self):
        import base64

        test_data = b"hello"
        b64 = base64.b64encode(test_data).decode()
        result = get_base64_value(b64)
        assert isinstance(result, str)

    def test_non_base64(self):
        result = get_base64_value("not_valid_base64!!!")
        assert result == "not_valid_base64!!!"


class TestS2N:
    def test_basic_conversion(self):
        assert s2n(b"a") == 97
        assert s2n(b"ab") == 24930

    def test_empty_string(self):
        assert s2n(b"") == 0

    def test_hexlify_format(self):
        result = s2n(b"test")
        expected = int("74657374", 16)
        assert result == expected


class TestN2S:
    def test_basic_conversion(self):
        result = n2s(97)
        assert result == b"a"

    def test_odd_length_hex(self):
        result = n2s(0xFFF)
        assert isinstance(result, bytes)

    def test_roundtrip(self):
        original = b"hello world"
        num = s2n(original)
        restored = n2s(num)
        assert restored == original


class TestBinarySearch:
    def test_found_element(self):
        arr = [1, 3, 5, 7, 9, 11]
        assert binary_search(arr, 7) == 3
        assert binary_search(arr, 1) == 0
        assert binary_search(arr, 11) == 5

    def test_not_found(self):
        arr = [1, 3, 5, 7, 9, 11]
        assert binary_search(arr, 4) == -1
        assert binary_search(arr, 0) == -1
        assert binary_search(arr, 100) == -1

    def test_empty_list(self):
        assert binary_search([], 5) == -1

    def test_single_element(self):
        assert binary_search([5], 5) == 0
        assert binary_search([5], 3) == -1
