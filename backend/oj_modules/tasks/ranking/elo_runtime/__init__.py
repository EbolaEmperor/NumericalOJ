"""ELO 隔离对局运行时。

把一场 ELO 对局拆成三个平级容器：两个断网工作容器（可信运行器看管被测
代码）与一个保持联网的裁判容器（管理员评分脚本），由宿主侧仲裁者路由
消息并做看门狗。详见 ``arbiter.py`` 模块注释。

包内 ``bot_runner.py`` 与 ``elo_host_api.py`` 是挂载/复制进容器运行的独立
脚本，只依赖 Python 标准库，导入本包不会引入额外运行时依赖。
"""

from backend.oj_modules.tasks.ranking.elo_runtime.arbiter import (  # noqa: F401
    EloRuntimeError,
    IsolatedEloMatch,
    run_isolated_elo_match,
)

__all__ = ["EloRuntimeError", "IsolatedEloMatch", "run_isolated_elo_match"]
