"""Test package.

Made a package so that `from tests.fake_agent import …` resolves: pytest then inserts
the repository root on `sys.path` rather than the `tests` directory itself.
"""
