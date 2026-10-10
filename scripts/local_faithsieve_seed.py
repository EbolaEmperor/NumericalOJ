"""只向调用方提供的本机独立库写入 FaithSieve 演示数据，不启动评测。

文件均位于 runtime_root，旧样例和管理员口令只创建一次。供应商配置是显式
导入到独立 MySQL 库的操作，不是应用运行时的环境变量回退。
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from backend.oj_modules.security.credentials import hash_password


LOCAL_DATABASE = "faithsieve_local_test"
ADMIN_USERNAME = "faithsieve-admin"
PROBLEM_TITLE = "FaithSieve 本地样例：自然数平方和"
PROBLEM_CONTENT = (
    "证明对每个整数 $n\\geq 1$，都有\n\n"
    "$$\\sum_{k=1}^{n}k^2=\\frac{n(n+1)(2n+1)}{6}.$$\n\n"
    "请给出完整证明。"
)
ALIYUN_MODEL = "qwen3.5-plus-2026-04-20"
ALIYUN_MODEL_DOC = "https://help.aliyun.com/zh/model-studio/qwen3-5-plus"
ALIYUN_API_DOC = "https://help.aliyun.com/zh/model-studio/anthropic-api-messages"

_PROOFS = {
    "correct": (
        "Proof by induction",
        [
            "For every integer n >= 1, define S(n) = 1^2 + 2^2 + ... + n^2.",
            "We prove S(n) = n(n+1)(2n+1)/6 by induction.",
            "Base case n=1: S(1)=1=1*2*3/6.",
            "Assume S(n)=n(n+1)(2n+1)/6 for some n >= 1.",
            "Then S(n+1) = S(n) + (n+1)^2",
            "  = n(n+1)(2n+1)/6 + (n+1)^2",
            "  = (n+1)(2n^2+7n+6)/6",
            "  = (n+1)(n+2)(2n+3)/6.",
            "This is the required formula with n replaced by n+1.",
            "The base case and induction step establish the claim for all n >= 1.",
        ],
    ),
    "gap": (
        "Proof by induction",
        [
            "For every integer n >= 1, define S(n) = 1^2 + 2^2 + ... + n^2.",
            "We prove S(n) = n(n+1)(2n+1)/6 by induction.",
            "Base case n=1: S(1)=1=1*2*3/6.",
            "Assume S(n)=n(n+1)(2n+1)/6 for some n >= 1.",
            "Then S(n+1) = S(n) + (n+1)^2",
            "  = n(n+1)(2n+1)/6 + (n+1)^2",
            "  = (n+1)(n+2)(2n+1)/6.",
            "This is the required formula with n replaced by n+1.",
            "Therefore the formula holds for all integers n >= 1.",
        ],
    ),
}


def _require_local_database(conn):
    if str(getattr(conn, "host", "")).lower() not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("种子操作仅允许本机 MySQL 连接")
    with conn.cursor() as cursor:
        cursor.execute("SELECT DATABASE() AS database_name")
        row = cursor.fetchone() or {}
    if row.get("database_name") != LOCAL_DATABASE:
        raise ValueError(f"种子操作仅允许独立库 {LOCAL_DATABASE}")


def _pdf_bytes(title: str, lines: list[str]) -> bytes:
    """生成一页带可提取 ASCII 原文的 PDF，无额外依赖或外部程序。"""
    def literal(text):
        return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    commands = ["BT /F1 18 Tf 42 750 Td", f"({literal(title)}) Tj", "/F1 11 Tf 0 -38 Td"]
    for line in lines:
        commands.extend((f"({literal(line)}) Tj", "0 -24 Td"))
    commands.append("ET")
    stream = "\n".join(commands).encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    document = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(document))
        document.extend(f"{number} 0 obj\n".encode() + body + b"\nendobj\n")
    start = len(document)
    document.extend(f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n".encode())
    for offset in offsets:
        document.extend(f"{offset:010d} 00000 n \n".encode())
    document.extend(f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{start}\n%%EOF\n".encode())
    return bytes(document)


def _write_new_file(root: Path, relative: str, content: bytes):
    path = root / relative
    if path.is_symlink() or not path.resolve().is_relative_to(root):
        raise ValueError("拒绝向隔离运行目录外写入样例文件")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as target:
            target.write(content)
    except FileExistsError:
        if not path.is_file():
            raise ValueError("样例文件路径被目录占用") from None


def _external_omni_configured(cursor):
    cursor.execute(
        "SELECT COUNT(*) AS total FROM llm_endpoints WHERE category='omni' "
        "AND CHAR_LENGTH(TRIM(api_key))>0 "
        "AND base_url NOT REGEXP '^https?://(127[.]0[.]0[.]1|localhost)(:|/)'")
    return bool((cursor.fetchone() or {}).get("total"))


def seed_local_demo(conn, runtime_root: Path, admin_password: str) -> dict:
    _require_local_database(conn)
    if not admin_password:
        raise ValueError("本地管理员口令不能为空")
    root = Path(runtime_root).absolute()
    if root.is_symlink():
        raise ValueError("隔离运行目录不能是符号链接")
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    manifest_path = root / "seed" / "faithsieve-demo.json"
    if manifest_path.is_symlink() or not manifest_path.resolve().is_relative_to(root):
        raise ValueError("样例清单不能位于隔离运行目录外")
    manifest = json.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
    submissions = []
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id,is_admin FROM users WHERE username=%s", (ADMIN_USERNAME,))
            admin = cursor.fetchone()
            if admin is None:
                cursor.execute(
                    "INSERT INTO users (username,password_hash,is_admin,email) VALUES (%s,%s,1,%s)",
                    (ADMIN_USERNAME, hash_password(admin_password), "faithsieve-admin@localhost.invalid"),
                )
            elif not admin.get("is_admin"):
                raise ValueError("同名账号已存在且不是管理员，拒绝修改该账号")

            if manifest.get("problem_id"):
                cursor.execute("SELECT id,type,written_grading_mode FROM problems WHERE id=%s", (manifest["problem_id"],))
            else:
                cursor.execute("SELECT id,type,written_grading_mode FROM problems WHERE title=%s ORDER BY id LIMIT 1", (PROBLEM_TITLE,))
            problem = cursor.fetchone()
            if problem is None:
                cursor.execute(
                    "INSERT INTO problems (title,content,initial_code,type,lang,max_score,written_grading_mode) "
                    "VALUES (%s,%s,'',2,'latex',5,4)", (PROBLEM_TITLE, PROBLEM_CONTENT),
                )
                problem_id = int(cursor.lastrowid)
            else:
                if int(problem.get("type") or 0) != 2 or int(problem.get("written_grading_mode") or 0) != 4:
                    raise ValueError("已有样例题已改为其他评测方式，拒绝覆盖")
                problem_id = int(problem["id"])

            previous = manifest.get("submission_ids_by_variant") or {}
            for variant, (title, lines) in _PROOFS.items():
                username = f"faithsieve-{variant}"
                cursor.execute("SELECT id FROM users WHERE username=%s", (username,))
                if cursor.fetchone() is None:
                    cursor.execute(
                        "INSERT INTO users (username,password_hash,is_admin,email) VALUES (%s,%s,0,%s)",
                        (username, hash_password(admin_password), f"{username}@localhost.invalid"),
                    )
                filename = f"faithsieve-demo-{variant}.pdf"
                recorded_id = previous.get(variant)
                if recorded_id:
                    cursor.execute("SELECT id,username,problem_id FROM submissions WHERE id=%s", (recorded_id,))
                else:
                    cursor.execute(
                        "SELECT id,username,problem_id FROM submissions WHERE username=%s AND problem_id=%s "
                        "AND test_points=%s ORDER BY id LIMIT 1", (username, problem_id, json.dumps(filename)),
                    )
                submission = cursor.fetchone()
                if submission is None:
                    cursor.execute(
                        "INSERT INTO submissions (problem_id,username,code,score,test_points,status,problem_title,problem_type) "
                        "VALUES (%s,%s,'',0,%s,'Pending',%s,2)",
                        (problem_id, username, json.dumps(filename), PROBLEM_TITLE),
                    )
                    submission_id = int(cursor.lastrowid)
                else:
                    if submission["username"] not in (username, ADMIN_USERNAME) or int(submission["problem_id"]) != problem_id:
                        raise ValueError("样例清单与已有提交身份不一致")
                    submission_id = int(submission["id"])
                _write_new_file(root, f"uploads/{submission_id}/{filename}", _pdf_bytes(title, lines))
                # 原稿只有一份正文来源；TEX 与 PDF 不各自维护会漂移的证明文本。
                tex = ("\\documentclass{article}\n\\begin{document}\n\\section*{" + title + "}\n"
                       "\\begin{verbatim}\n" + "\n".join(lines) + "\n\\end{verbatim}\n\\end{document}\n")
                _write_new_file(root, f"uploads/{submission_id}/faithsieve-demo-{variant}.tex", tex.encode())
                submissions.append({"id": submission_id, "variant": variant,
                                    "username": submission["username"] if submission else username,
                                    "detail_url": f"/submissions/{submission_id}"})
            configured = _external_omni_configured(cursor)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    manifest = {"problem_id": problem_id, "submission_ids_by_variant": {item["variant"]: item["id"] for item in submissions}}
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    return {"admin_username": ADMIN_USERNAME, "problem_id": problem_id,
            "submission_ids": [item["id"] for item in submissions], "submissions": submissions,
            "real_model_configured": configured}


def _read_provider_env(path: Path):
    values = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            raise ValueError("本地供应商配置格式无效")
        key, value = line.split("=", 1)
        key = key.strip()
        if key in values:
            raise ValueError("本地供应商配置包含重复键")
        value = value.strip()
        if value.startswith('"'):
            try:
                value = json.loads(value)
            except ValueError:
                raise ValueError("本地供应商配置引号格式无效") from None
        elif value.startswith("'"):
            if not value.endswith("'"):
                raise ValueError("本地供应商配置引号格式无效")
            value = value[1:-1]
        if not isinstance(value, str):
            raise ValueError("本地供应商配置值必须是字符串")
        values[key] = value
    return values


def import_local_provider_config(conn, env_path: Path) -> dict:
    """按官方固定快照资料导入北京百炼节点；不调用供应商、不改已有配置。"""
    _require_local_database(conn)
    with conn.cursor() as cursor:
        cursor.execute("SELECT id,model,protocol,category,test_status FROM llm_endpoints ORDER BY id LIMIT 1")
        existing = cursor.fetchone()
        if existing:
            return {"imported": False,
                    "endpoint_id": int(existing["id"]), "model": existing["model"],
                    "protocol": existing["protocol"], "category": existing["category"],
                    "test_status": existing["test_status"], "message": "独立库已有模型配置，保留现有设置"}
    values = _read_provider_env(Path(env_path))
    api_key = values.get("ALIYUN_API_KEY", "").strip()
    base_url = values.get("ALIYUN_ANTHROPIC_URL", "").strip().rstrip("/")
    if not api_key or not base_url:
        return {"imported": False, "message": "未找到完整的阿里云 Anthropic 配置"}
    try:
        parsed = urlsplit(base_url)
        port = parsed.port
    except ValueError:
        raise ValueError("本地阿里云网关地址格式无效") from None
    if (
        parsed.scheme != "https" or parsed.username or parsed.password or parsed.query or parsed.fragment
        or port not in (None, 443)
        or not re.fullmatch(r"llm-[a-z0-9-]+\.cn-beijing\.maas\.aliyuncs\.com", parsed.hostname or "")
        or parsed.path != "/apps/anthropic"
    ):
        raise ValueError("仅自动导入官方北京业务空间的 Anthropic 网关")
    # 固定快照支持图像及 Function Calling；上下文主动限制到最低价格阶梯。
    # 原价来源：ALIYUN_MODEL_DOC；cached 字段是显式缓存命中，不是缓存创建。
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE username=%s AND is_admin=1", (ADMIN_USERNAME,))
            admin = cursor.fetchone()
            if admin is None:
                raise ValueError("请先创建独立库的本地管理员")
            cursor.execute(
                "INSERT INTO llm_endpoints (protocol,category,base_url,api_key,model,context_window_tokens,max_output_tokens,"
                "thinking_enabled,thinking_format,input_price_per_million,cached_input_price_per_million,output_price_per_million,"
                "test_status,test_message,created_by_user_id,updated_by_user_id) "
                "VALUES ('anthropic','omni',%s,%s,%s,128000,32000,0,'none',0.8,0.08,4.8,'untested',%s,%s,%s)",
                (base_url, api_key, ALIYUN_MODEL, "按官方资料导入，尚未发起模型请求", int(admin["id"]), int(admin["id"])),
            )
            endpoint_id = int(cursor.lastrowid)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {"imported": True, "endpoint_id": endpoint_id,
            "model": ALIYUN_MODEL, "category": "omni", "protocol": "anthropic",
            "context_window_tokens": 128000, "max_output_tokens": 32000,
            "input_price_per_million": "0.8", "cached_input_price_per_million": "0.08", "output_price_per_million": "4.8",
            "test_status": "untested", "harnesses": ["pi", "claude_code"],
            "references": [ALIYUN_MODEL_DOC, ALIYUN_API_DOC]}
