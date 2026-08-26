#!/usr/bin/env python3
"""
meridian.py — entrypoint shim.

This file delegates to cli.py so that direct invocations work:

    python meridian.py policies/
    python meridian.py policy.json --severity high
    python meridian.py policies/ --output json

All new flags are available through this shim.
"""
import sys
import os

# Ensure the repo root is on sys.path so meridian package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cli import main  # noqa: E402

if __name__ == "__main__":
    main()
