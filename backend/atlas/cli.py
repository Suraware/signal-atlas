"""One production process serves the interface and local API."""

import argparse
from pathlib import Path

import uvicorn

from .app import create_app
from .security import lan_addresses


def main():
    parser = argparse.ArgumentParser(description="Signal Atlas: local-first security research workbench")
    parser.add_argument("--lan", action="store_true", help="Listen on the existing LAN (trusted network only).")
    parser.add_argument("--port", type=int, default=8731)
    parser.add_argument("--data-dir", type=Path, default=Path.cwd() / "data")
    parser.add_argument("--refresh-minutes", type=int, default=0, help="Refresh public feeds automatically (0 disables; minimum 15).")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("The port must be between 1 and 65535.")
    if args.refresh_minutes and args.refresh_minutes < 15:
        parser.error("Automatic refresh must be at least 15 minutes to respect public feed budgets.")
    print(f"\nSignal Atlas → http://localhost:{args.port}")
    print(f"Local database: {args.data_dir.resolve() / 'atlas.sqlite3'}")
    if args.lan:
        for address in lan_addresses():
            print(f"LAN → http://{address}:{args.port}")
        print("Trusted LAN only: anyone who can reach this listener can read and edit the workspace. No firewall rules were changed.")
    if args.refresh_minutes:
        print(f"Public no-key feed refresh: startup, then every {args.refresh_minutes} minutes (source TTLs apply).")
    app = create_app(args.data_dir, refresh_seconds=args.refresh_minutes * 60)
    uvicorn.run(app, host="0.0.0.0" if args.lan else "127.0.0.1", port=args.port, log_level="info")


if __name__ == "__main__":
    main()
