"""打榜赛批量 Git 仓库命名、探测与提交信息读取。"""

import os
import re
import shutil
import subprocess
import tempfile

from backend.oj_modules import config as _cfg


PLACEHOLDER = "<username>"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_.\-]*$")
# 这是批量评测页的产品文案，不是部署配置。
BATCH_DEFAULT_TEMPLATE = "gitea@10.72.190.121:<username>/FinalProject.git"
GIT_LSREMOTE_TIMEOUT = int(getattr(_cfg, "RANKING_BATCH_LSREMOTE_TIMEOUT", 20))
GIT_CLONE_TIMEOUT = int(getattr(_cfg, "RANKING_BATCH_CLONE_TIMEOUT", 180))


def _git_env():
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env.setdefault(
        "GIT_SSH_COMMAND",
        "ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10",
    )
    return env


def build_repo_url(template, username):
    return (template or "").replace(PLACEHOLDER, username)


def repo_exists(url):
    if not url or url.startswith("-"):
        return False, "非法的仓库地址"
    try:
        proc = subprocess.run(
            ["git", "ls-remote", url],
            env=_git_env(),
            capture_output=True,
            text=True,
            timeout=GIT_LSREMOTE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return False, "探测超时"
    except Exception as exc:  # pragma: no cover
        return False, f"探测失败：{exc}"
    if proc.returncode == 0:
        return True, "ok"
    lines = (proc.stderr or proc.stdout or "").strip().splitlines()
    return False, lines[0].strip() if lines else f"git 退出码 {proc.returncode}"


def _clone_to_dir(url, clone_dir):
    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", url, clone_dir],
            env=_git_env(),
            capture_output=True,
            text=True,
            timeout=GIT_CLONE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return False, f"git clone 超时（>{GIT_CLONE_TIMEOUT}s）"
    except Exception as exc:  # pragma: no cover
        return False, f"git clone 异常：{str(exc)[:200]}"
    if proc.returncode != 0:
        lines = [
            line.strip()
            for line in (proc.stderr or proc.stdout or "").splitlines()
            if line.strip()
        ]
        picked = ""
        for line in lines:
            lowered = line.lower()
            if (
                "gitea:" in lowered
                or "cannot find" in lowered
                or line.startswith("fatal:")
                or "denied" in lowered
                or "not found" in lowered
            ):
                picked = line
                break
        if not picked:
            picked = lines[-1] if lines else f"退出码 {proc.returncode}"
        return False, "git clone 失败：" + picked.replace("remote:", "").strip()[:200]
    return True, ""


def repo_last_commit(url):
    if not url or url.startswith("-"):
        return False, None, "非法的仓库地址"
    temp_root = tempfile.mkdtemp(prefix="rankcheck_")
    clone_dir = os.path.join(temp_root, "repo")
    try:
        ok, error = _clone_to_dir(url, clone_dir)
        if not ok:
            return False, None, error
        try:
            separator = "\x1f"
            fmt = separator.join(["%H", "%h", "%an", "%aI", "%s", "%b"])
            proc = subprocess.run(
                ["git", "-C", clone_dir, "log", "-1", "--pretty=format:" + fmt],
                env=_git_env(),
                capture_output=True,
                text=True,
                timeout=GIT_LSREMOTE_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return True, None, "读取提交信息超时"
        except Exception as exc:  # pragma: no cover
            return True, None, f"读取提交信息失败：{str(exc)[:200]}"
        if proc.returncode != 0:
            return True, None, "仓库为空（无任何提交）"
        parts = (proc.stdout or "").split(separator)
        while len(parts) < 6:
            parts.append("")
        return True, {
            "hash": parts[0].strip(),
            "short": parts[1].strip(),
            "author": parts[2].strip(),
            "date_iso": parts[3].strip(),
            "subject": parts[4].strip(),
            "body": parts[5].strip(),
        }, "ok"
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


__all__ = [
    "PLACEHOLDER",
    "USERNAME_RE",
    "BATCH_DEFAULT_TEMPLATE",
    "GIT_LSREMOTE_TIMEOUT",
    "GIT_CLONE_TIMEOUT",
    "build_repo_url",
    "repo_exists",
    "repo_last_commit",
]
