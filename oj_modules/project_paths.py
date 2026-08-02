"""项目内稳定路径入口。

业务模块不应根据自身 ``__file__`` 的目录深度推导项目根；模块迁入子包后，
这类推导会静默指向错误位置。项目根只在这个固定入口计算一次。
"""

from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent


__all__ = ["PACKAGE_ROOT", "PROJECT_ROOT"]
