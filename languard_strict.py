#!/usr/bin/env python3
"""
Entry point for commands that lower protection (pause, protect --off,
unblock, ...). Its polkit action (org.languard.weaken) asks for your password
every time, so malware can't reuse one you typed a minute ago. Same commands
as languard.py; see languard_core/tamper.py.
"""
import os
import runpy
import sys
from pathlib import Path

os.environ["LANGUARD_STRICT"] = "1"
script = Path(__file__).resolve().parent / "languard.py"
sys.argv[0] = str(script)
runpy.run_path(str(script), run_name="__main__")
