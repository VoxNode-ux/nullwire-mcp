"""Launcher for the NullWire-MCP binary. Standard library only.

Downloads the binary for this platform from the GitHub release on first run,
verifies it against SHA256SUMS.txt, caches it, then runs it with the same
arguments and the same stdin/stdout (so it works as an MCP stdio server).
"""
import hashlib
import os
import platform
import re
import signal
import subprocess
import sys
import tempfile
import urllib.request

__version__ = "1.2.0"

REPO = "VoxNode-ux/nullwire-mcp"
RELEASE = os.environ.get("NULLWIRE_VERSION") or "v" + __version__
BASE_URL = (
    os.environ.get("NULLWIRE_BASE_URL")
    or "https://github.com/%s/releases/download/%s" % (REPO, RELEASE)
).rstrip("/")


def _log(msg):
    sys.stderr.write("nullwire-mcp: %s\n" % msg)  # never stdout: that is the MCP channel
    sys.stderr.flush()


def _fail(msg):
    _log(msg)
    sys.exit(1)


def _asset_name():
    system = platform.system().lower()
    machine = platform.machine().lower()
    os_name = {"linux": "linux", "darwin": "darwin", "windows": "windows"}.get(system)
    cpu = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    if os_name == "windows":
        cpu = "amd64"  # Windows on ARM runs the x64 build
    if not os_name or not cpu:
        _fail("no prebuilt binary for %s/%s. Build from source: https://github.com/%s" % (system, machine, REPO))
    return "nullwire-%s-%s%s" % (os_name, cpu, ".exe" if os_name == "windows" else "")


def _cache_dir():
    override = os.environ.get("NULLWIRE_CACHE_DIR")
    if override:
        return override
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
    elif sys.platform == "darwin":
        base = os.path.join(home, "Library", "Caches")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or os.path.join(home, ".cache")
    return os.path.join(base, "nullwire-mcp", re.sub(r"[^\w.-]", "_", RELEASE))


def _get(url):
    if not url.startswith(("https://", "http://")):
        raise ValueError("unsupported URL: %s" % url)
    req = urllib.request.Request(url, headers={"User-Agent": "nullwire-mcp-pypi"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # follows redirects
        return resp.read()


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _expected_hash(sums, asset):
    for line in sums.splitlines():
        m = re.match(r"^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$", line)
        if m and m.group(2) == asset:
            return m.group(1).lower()
    return None


def _ensure_binary():
    asset = _asset_name()
    folder = _cache_dir()
    binary = os.path.join(folder, asset)
    sidecar = binary + ".sha256"

    # A cached copy is used only if it still matches the hash recorded when it was verified.
    try:
        with open(sidecar, "r") as fh:
            want = fh.read().strip()
        with open(binary, "rb") as fh:
            if _sha256(fh.read()) == want:
                return binary
        _log("the cached binary does not match its recorded checksum; downloading it again")
    except OSError:
        pass

    _log("downloading %s (%s)" % (asset, RELEASE))
    try:
        data = _get("%s/%s" % (BASE_URL, asset))
        sums = _get("%s/SHA256SUMS.txt" % BASE_URL).decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 - any network problem is a clean failure
        _fail("download failed: %s" % exc)
    want = _expected_hash(sums, asset)
    if not want:
        _fail("SHA256SUMS.txt has no entry for %s" % asset)
    got = _sha256(data)
    if got != want:
        _fail("checksum mismatch for %s (expected %s, got %s); not running it" % (asset, want, got))

    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, suffix=".tmp")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(tmp, 0o755)
    os.replace(tmp, binary)
    with open(sidecar, "w") as fh:
        fh.write(got + "\n")
    _log("checksum OK")
    return binary


def main():
    args = sys.argv[1:]
    binary = _ensure_binary()
    if args and args[0] == "--nullwire-prefetch":
        _log("ready: %s" % binary)
        return 0
    env = dict(os.environ, NULLWIRE_VIA_PYTHON="1")
    try:
        proc = subprocess.Popen([binary] + args, env=env)
    except OSError as exc:
        _fail("could not start %s: %s" % (binary, exc))
    for name in ("SIGINT", "SIGTERM", "SIGHUP"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, lambda s, _f: proc.send_signal(s))
            except (ValueError, OSError):
                pass
    return proc.wait()


if __name__ == "__main__":
    sys.exit(main())
