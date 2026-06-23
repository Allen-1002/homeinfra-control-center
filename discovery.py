"""Compatibility entrypoint for `python3 -m unittest -v discovery`."""

import unittest


def load_tests(loader, tests, pattern):
    return loader.discover("tests")


if __name__ == "__main__":
    unittest.main()
