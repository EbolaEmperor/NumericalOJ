# -*- coding: utf-8 -*-
"""E2E 专用 Flask 入口：只监听 loopback，且绝不启动 debug reloader。"""

from __future__ import annotations


LOOPBACK_HOST = "127.0.0.1"
LOOPBACK_PORT = 2025


def main() -> None:
    from oj import app, ensure_background_schedulers

    app.config["DEBUG"] = False
    ensure_background_schedulers()
    app.run(
        host=LOOPBACK_HOST,
        port=LOOPBACK_PORT,
        debug=False,
        use_reloader=False,
        threaded=True,
    )


if __name__ == "__main__":
    main()
