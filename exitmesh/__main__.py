#!/usr/bin/env python3
"""Entry point: python3 -m exitmesh  /  exitmesh-panel"""

import os
import sys

from .panel import serve


def main():
    db = os.environ.get("EXITMESH_DB", "/var/lib/exitmesh/exitmesh.db")
    xray = os.environ.get("EXITMESH_XRAY", "/usr/local/bin/xray")
    listen = os.environ.get("EXITMESH_LISTEN", "127.0.0.1")
    port = os.environ.get("EXITMESH_PORT")
    serve(db, xray_bin=xray, listen=listen, port=int(port) if port else None)


if __name__ == "__main__":
    main()
