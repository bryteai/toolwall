"""Unit tests exercise the policy and rule layers deterministically; the ML judge is
evaluated separately (eval/, results/), so it is disabled for the test suite."""
import os

os.environ.setdefault("TOOLWALL_DISABLE_JUDGE", "1")
