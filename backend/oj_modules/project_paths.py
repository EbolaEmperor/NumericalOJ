"""项目内稳定路径入口。

业务模块不应根据自身 ``__file__`` 的目录深度推导项目根；模块迁入子包后，
这类推导会静默指向错误位置。项目根只在这个固定入口计算一次。
"""

from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent
BACKEND_ROOT = PACKAGE_ROOT.parent
PROJECT_ROOT = BACKEND_ROOT.parent
FRONTEND_ROOT = PROJECT_ROOT / "frontend"
FRONTEND_PUBLIC_ROOT = FRONTEND_ROOT / "public"
FRONTEND_DIST_ROOT = FRONTEND_ROOT / "dist"


__all__ = [
    "BACKEND_ROOT",
    "FRONTEND_DIST_ROOT",
    "FRONTEND_PUBLIC_ROOT",
    "FRONTEND_ROOT",
    "PACKAGE_ROOT",
    "PROJECT_ROOT",
]
