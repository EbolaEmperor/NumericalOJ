#!/usr/bin/env python3
"""在镜像末层选择公开或教学 socket，复用稳定协议并保留旧入口。"""

from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
import sys


RELAY_PATH = "/usr/local/lib/vibehub_uds_relay.py"


def main() -> int:
    arguments = sys.argv[1:]
    if arguments not in ([], ["--edu"]):
        return 64
    loader = SourceFileLoader("vibehub_uds_relay", RELAY_PATH)
    spec = spec_from_loader(loader.name, loader)
    relay = module_from_spec(spec)
    loader.exec_module(relay)
    if arguments == ["--edu"]:
        relay.SOCKET_PATH = "/run/vibehub/edu.sock"
    return relay.main()


if __name__ == "__main__":
    raise SystemExit(main())
