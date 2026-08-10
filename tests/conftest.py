# test_auth.py is a self-contained, self-checking script (run: `python tests/test_auth.py`)
# that mirrors the TG-01..TG-04 test reports in docs/test-reports/. It reports results via
# print() and sys.exit(), so it is not a pytest module. Exclude it from collection; the
# pytest-native suite lives in test_unit.py.
collect_ignore = ["test_auth.py"]
