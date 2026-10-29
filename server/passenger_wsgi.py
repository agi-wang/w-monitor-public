"""DirectAdmin/Passenger entrypoint; all source and configuration stay private."""
import os
import sys
from pathlib import Path
import site
import stat

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
runtime = Path(__file__).resolve().parents[1] / "runtime"
packages = runtime / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
if packages.is_dir():
    site.addsitedir(str(packages))
# The hosting gate writes this owner-only pointer outside the document root.
# Some cPanel Apache builds omit mod_env and cannot accept SetEnv directives.
if "WM_PUBLIC_CONFIG" not in os.environ:
    pointer = Path(__file__).resolve().parents[1] / "config-path"
    descriptor = os.open(pointer, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise RuntimeError("Private configuration pointer required")
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise RuntimeError("Configuration pointer exceeds bound")
    config = raw.decode().strip()
    if not Path(config).is_absolute():
        raise RuntimeError("Absolute private configuration path required")
    os.environ["WM_PUBLIC_CONFIG"] = config
from app import application  # noqa: E402,F401
