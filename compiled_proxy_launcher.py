import os
import sys
from pathlib import Path

from mitmproxy.tools.main import mitmdump


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def resource_path(relative_path: str) -> Path:
    base_dir = app_dir()
    candidate = base_dir / relative_path
    if candidate.exists():
        return candidate

    bundle_dir = getattr(sys, "_MEIPASS", None)
    if bundle_dir:
        bundled_candidate = Path(bundle_dir) / relative_path
        if bundled_candidate.exists():
            return bundled_candidate

    return candidate


def main() -> int:
    base_dir = app_dir()
    os.chdir(base_dir)

    script_path = resource_path("sap_reverse_proxy_mitm.py")

    missing = [path for path in (script_path,) if not path.exists()]
    if missing:
        for path in missing:
            print(f"Required file not found: {path}", file=sys.stderr)
        return 1

    listen_host = os.environ.get("GB_MITM_LISTEN_HOST", "0.0.0.0")
    listen_port = os.environ.get("GB_MITM_LISTEN_PORT", "1337")
    s4_upstream = os.environ.get("GB_MITM_S4_UPSTREAM", "https://s4.example.invalid/")

    args = [
        "--set",
        "http2=false",
        "--set",
        "connection_strategy=lazy",
        "--listen-host",
        listen_host,
        "--listen-port",
        listen_port,
        "--mode",
        f"reverse:{s4_upstream}",
        "--ssl-insecure",
        "-s",
        str(script_path),
    ]

    cert_args = os.environ.get("GB_MITM_CERTS", "").split()
    if cert_args:
        args.extend(cert_args)

    return mitmdump(args) or 0


if __name__ == "__main__":
    raise SystemExit(main())
