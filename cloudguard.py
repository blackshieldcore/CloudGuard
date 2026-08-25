#!/usr/bin/env python3
"""
cloudguard.py — backward-compatibility shim.

This file replaces the original single-file cloudguard.py.
It delegates to cli.py so that the original invocation still works:

    python cloudguard.py policies/
    python cloudguard.py policy.json --severity high
    python cloudguard.py policies/ --output json

All new flags are also available through this shim.
"""
import sys
import os

# Ensure the repo root is on sys.path so cloudguard package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cli import main  # noqa: E402

if __name__ == "__main__":
    main()
