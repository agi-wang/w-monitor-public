"""DirectAdmin/Passenger entrypoint; all source and configuration stay private."""
import os
import sys
from pathlib import Path
import site

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
runtime = Path(__file__).resolve().parents[1] / "runtime"
packages = runtime / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
if packages.is_dir():
    site.addsitedir(str(packages))
from app import application  # noqa: E402,F401
