# NumericalOJ Docker CI（why-server）

本目录是 NumericalOJ 的容器化测试（CI）配置：在 **真实 MySQL + Redis + 真实判题工具链（gcc/g++/python3/octave）** 的隔离环境中逐模块跑 pytest。CI 运行在 why-server 上独立的目录 `/home/ebola/oj-ci`，使用独立镜像与独立的 mysql/redis 容器，**绝不触碰生产部署 `/home/ebola/oj` 及其 `config.py`**。

> 🛠 **首次给一台主机装 Docker** 才需要看 [`INSTALL-DOCKER.md`](./INSTALL-DOCKER.md)（含 why-server 上的完整安装命令与踩坑记录）。本文件只讲**日常怎么用 CI**。

---

## 1. 前置条件

- **why-server 已装 Docker + Compose 插件**，且当前用户能免 sudo 跑 docker。本机检测：
  ```bash
  ssh why-server 'docker --version && docker compose version'
  ```
  没装好见 [`INSTALL-DOCKER.md`](./INSTALL-DOCKER.md)。
- **本机能 `ssh why-server`**（SSH alias 已配好，远程用户 `ebola`）。
- **why-server 已配 registry 镜像加速**（拉 `mysql:8.0`/`redis:7`/`debian:12-slim` 用），否则会超时——同见 [`INSTALL-DOCKER.md`](./INSTALL-DOCKER.md)。

---

## 2. 一键运行（最常用）

在本机仓库根执行：

```bash
bash tests/ci/run-on-why-server.sh
```

它做四件事：

1. **同步**：`rsync --delete` 把本机代码推到 why-server 的 `/home/ebola/oj-ci`（排除 `.git`/`__pycache__`/`tmp/`/`uploads/`/`static/`/`competitions/`/`test-results/`）。`--delete` 只作用于这个独立 CI 目录。
2. **构建并运行**：`docker compose -f tests/ci/docker-compose.ci.yml up --build --abort-on-container-exit --exit-code-from test`，等 mysql/redis healthy 后逐模块跑测试。
3. **拉回结果**：远端 `test-results/`（JUnit XML）同步回本机 `./test-results/`。
4. **清理**：`docker compose ... down -v` 删除测试容器与数据卷。

脚本以 `test` 容器的退出码作为整体退出码（全绿 = 0）。

### 环境变量覆盖

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `REMOTE` | `why-server` | SSH 目标主机（alias 或 `user@host`） |
| `REMOTE_DIR` | `/home/ebola/oj-ci` | 远端独立 CI 目录 |

```bash
REMOTE=other-host REMOTE_DIR=/home/me/oj-ci bash tests/ci/run-on-why-server.sh
```

---

## 3. 只跑单个模块 / 单个用例

CI 已 `up --build` 至少一次（镜像存在、mysql/redis 在跑）后，可只跑某文件而不重建整套。在 why-server 的 `/home/ebola/oj-ci` 下：

```bash
docker compose -f tests/ci/docker-compose.ci.yml run --rm test \
    python3 -m pytest tests/integration/test_auth.py -v
# 单用例：
docker compose -f tests/ci/docker-compose.ci.yml run --rm test \
    python3 -m pytest tests/integration/test_submission.py::test_submission_status_json -v
```

`run --rm test` 复用同一镜像与已就绪的 mysql/redis 依赖，单独起一个一次性容器跑指定测试，结束自动删除。把路径换成 `tests/unit`、`tests/db` 等即可。

---

## 4. 看结果

- **终端汇总表**：`run-ci.sh` 结尾按模块打印：
  ```
  =================== 汇总 ===================
  tests/unit                                    ✅ PASS
  tests/db                                      ✅ PASS
  tests/integration/test_auth.py                ❌ FAIL(1)
  ...
  ===========================================
  ```
- **JUnit XML**：每个模块一份 `test-results/<模块路径转义>.xml`（如 `tests_integration_test_auth_py.xml`），一键脚本会拉回本机 `./test-results/`，可喂给任意 JUnit 报告工具。

---

## 5. 目录布局（`tests/ci/`）

| 文件 | 职责 |
| --- | --- |
| `Dockerfile` | 基于 `debian:12-slim` 构建测试镜像：装 `python3`、`gcc/g++/build-essential`、`octave`、`coreutils`（沙箱用 `timeout`）、`default-mysql-client`、`ca-certificates`，并 `pip install` 依赖；`COPY . /app/` 后用 `config.ci.py` 覆盖 `/app/config.py`。针对 why-server 的网络做了加固：apt 强制 IPv4 + 切清华 Debian 镜像、pip 走清华源；并设 `PIP_BREAK_SYSTEM_PACKAGES=1`（Debian 12 PEP 668）。 |
| `docker-compose.ci.yml` | 编排 `mysql`（mysql:8.0，utf8mb4，把仓库根 `myojdb.sql` 挂到 `/docker-entrypoint-initdb.d/` 预灌 schema，带 healthcheck）、`redis`（redis:7，带 healthcheck）、`test`（用本目录 Dockerfile 构建，`depends_on` 两者 healthy，挂出 `test-results/`，跑 `run-ci.sh`）。文件在 `tests/ci/`，内部用 `../../` 指向仓库根。 |
| `config.ci.py` | **自包含**的 CI 配置（不能 `from config import *`）。MySQL/Redis 指向 compose 服务名 `mysql`/`redis`；AI/SMTP 用非空 dummy（测试里全程 mock 网络 AI）。构建时覆盖 `/app/config.py`。 |
| `run-ci.sh` | 在 `test` 容器内**逐模块顺序**跑 pytest（unit → db → integration 各文件），逐模块打印结果并写 `test-results/<safe>.xml`（JUnit），最后打印汇总表；任一模块失败则整体非零退出。 |
| `run-on-why-server.sh` | 本机执行的一键编排（见第 2 节）。 |
| `INSTALL-DOCKER.md` | 一次性的 Docker 安装记录 + 踩坑（仅装机时看）。 |

> 构建上下文排除项在**仓库根的 `.dockerignore`**（`.git`/`__pycache__`/`tmp/`/`uploads/`/`static/`/`competitions/`/`docs/`/`test-results/`），减小上下文。

---

## 6. 隔离保证（重要）

- CI 全程运行在 **`/home/ebola/oj-ci`**，与生产部署 **`/home/ebola/oj` 完全隔离**。
- 使用**独立测试镜像** + **独立 mysql/redis 容器**（compose 内联，结束即 `down -v` 删卷）。生产 MySQL/Redis 不受影响。
- CI 配置来自镜像内的 `config.ci.py`，**绝不读取也绝不改写生产 `config.py`**。
- 同步脚本的 `rsync --delete` **只作用于 `/home/ebola/oj-ci`**。

---

## 7. 排错

- **mysql 未就绪 / 连不上**：`test` 依赖 `mysql: condition: service_healthy`，正常会等。仍报连不上就看日志：`docker compose -f tests/ci/docker-compose.ci.yml logs mysql`。`conftest.py` 还有 `_wait_for_mysql`（~90s）兜底。
- **schema 未灌入 / 改了 `myojdb.sql` 不生效**：`myojdb.sql` 只在 **mysql 数据卷首次初始化**时执行；卷里有旧数据就不会重灌。用 `docker compose -f tests/ci/docker-compose.ci.yml down -v`（`-v` 删卷）后重跑强制重灌。
- **判题用例失败（找不到 octave/gcc）**：改了 `Dockerfile` 要 `up --build` 重建镜像。
- **`PIP_BREAK_SYSTEM_PACKAGES`**：进容器手动 pip 时需带它（或 `pip3 install --break-system-packages`）。
- **拉基础镜像超时**：why-server 直连 Docker Hub 不通，必须配 registry 镜像，见 [`INSTALL-DOCKER.md`](./INSTALL-DOCKER.md)。
- **进容器手动调试**：
  ```bash
  docker compose -f tests/ci/docker-compose.ci.yml run --rm test bash
  # 容器内: python3 -m pytest tests/... -v、查 /app/config.py、连 mysql/redis
  ```

---

## 8. 本机（mac）直接跑（可选，需 Docker Desktop）

```bash
docker compose -f tests/ci/docker-compose.ci.yml up --build --abort-on-container-exit --exit-code-from test
```

结果同样落在本机 `./test-results/`。mac 多为 arm64，会拉对应架构的多架构镜像，首跑较慢。
