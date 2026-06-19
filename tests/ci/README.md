# NumericalOJ Docker CI

本目录是 NumericalOJ 的容器化测试配置：在 **独立 MySQL + Redis + 真实判题工具链（gcc/g++/python3/octave）** 的隔离环境中逐模块跑 pytest。

**CI/test 绝对禁止在 `why-server` 上运行。** `why-server` 是本地 SSH config 里的生产主机别名，该主机自己的 hostname 是 `computing`；两者都视为同一台生产主机。生产主机只能用于生产部署和明确的运维操作；即使使用 Docker、独立目录、独立容器、独立 MySQL/Redis，也不能把它作为 CI runner。需要手动跑 CI 时，只能在本地开发机或另一台非生产服务器上运行。

---

## 1. 前置条件

- 本地开发机或非生产服务器已安装 Docker + Compose 插件。
- 当前用户可以运行 `docker` 和 `docker compose`。
- 运行环境不能是 `why-server` / host `computing`，也不能挂载或读取生产 `/home/ebola/oj/config.py`。

本地检查：

```bash
docker --version
docker compose version
```

首次给一台非生产服务器安装 Docker 时，可参考 [`INSTALL-DOCKER.md`](./INSTALL-DOCKER.md) 的通用安装排错内容；不要把其中的 `why-server` / `computing` 作为 CI 运行目标。

---

## 2. 本地一键运行

在仓库根目录执行：

```bash
docker compose -f tests/ci/docker-compose.local.yml up --build --abort-on-container-exit --exit-code-from test
```

它会构建测试镜像，启动独立的 `mysql` / `redis` 容器，等待服务 healthy 后运行 `tests/ci/run-ci.sh`，最后把 JUnit XML 写到本机 `./test-results/`。

清理测试容器和数据卷：

```bash
docker compose -f tests/ci/docker-compose.local.yml down -v --remove-orphans
```

---

## 3. 非生产服务器运行

如果本机资源不足，可以把 CI 跑在另一台明确的非生产服务器上。禁止使用 `why-server` / host `computing`。

可以使用历史遗留脚本 `run-on-why-server.sh`，但必须显式指定非生产目标；脚本会拒绝空目标、`why-server` 和远端 hostname 为 `computing` 的目标：

```bash
REMOTE=dev-ci-host \
REMOTE_DIR=/home/me/oj-ci \
bash tests/ci/run-on-why-server.sh
```

脚本会：

1. 用 `rsync --delete` 把本机代码同步到 `REMOTE_DIR`。
2. 在远端运行 `docker compose -f tests/ci/docker-compose.local.yml up --build --abort-on-container-exit --exit-code-from test`。
3. 把远端 `test-results/` 拉回本机 `./test-results/`。
4. 执行 `docker compose ... down -v --remove-orphans` 清理测试容器和数据卷。

可覆盖的环境变量：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `REMOTE` | 无 | 必填，必须是非生产 SSH 目标主机 |
| `REMOTE_DIR` | `/home/ebola/oj-ci` | 远端独立 CI 目录；在非生产服务器上可改成任意专用目录 |
| `COMPOSE_FILE` | `tests/ci/docker-compose.local.yml` | 远端使用的 compose 文件；默认不挂载生产路径 |

---

## 4. 只跑单个模块 / 单个用例

CI 已 `up --build` 至少一次后，可在同一台本地或非生产服务器上只跑某个文件：

```bash
docker compose -f tests/ci/docker-compose.local.yml run --rm test \
    python3 -m pytest tests/integration/test_auth.py -v

docker compose -f tests/ci/docker-compose.local.yml run --rm test \
    python3 -m pytest tests/integration/test_submission.py::test_submission_status_json -v
```

把路径换成 `tests/unit`、`tests/db` 等即可。仍然禁止在 `why-server` / host `computing` 上执行这些命令。

---

## 5. 看结果

- 终端汇总表：`run-ci.sh` 结尾按模块打印：
  ```text
  =================== 汇总 ===================
  tests/unit                                    PASS
  tests/db                                      PASS
  tests/integration/test_auth.py                FAIL(1)
  ...
  ===========================================
  ```
- JUnit XML：每个模块一份 `test-results/<模块路径转义>.xml`，可喂给任意 JUnit 报告工具。

---

## 6. 目录布局（`tests/ci/`）

| 文件 | 职责 |
| --- | --- |
| `Dockerfile` | 基于 `debian:12-slim` 构建测试镜像：安装 `python3`、`gcc/g++/build-essential`、`octave`、`coreutils`、`default-mysql-client`、`ca-certificates` 和 Python 依赖；构建时用 `config.ci.py` 覆盖 `/app/config.py`。 |
| `docker-compose.local.yml` | 推荐的本地/非生产 CI compose 文件；编排独立 `mysql`、`redis`、`test`，不挂载生产路径。 |
| `docker-compose.ci.yml` | 历史主机专用 compose 文件，包含宿主 MKL 挂载；日常 CI 优先使用 `docker-compose.local.yml`，且任何 compose 文件都不能在 `why-server` / host `computing` 上运行。 |
| `config.ci.py` | 自包含 CI 配置。MySQL/Redis 指向 compose 服务名 `mysql`/`redis`；AI/SMTP 使用测试占位值，测试中网络 AI 通常 mock 或 skip。 |
| `run-ci.sh` | 在 `test` 容器内逐模块顺序跑 pytest（unit -> db -> integration 各文件），逐模块打印结果并写 JUnit XML；任一模块失败则整体非零退出。 |
| `run-on-why-server.sh` | 历史遗留的远程编排脚本。现在只允许显式指定非生产 `REMOTE`，并会拒绝 `why-server` / host `computing`。 |
| `INSTALL-DOCKER.md` | Docker 安装记录和排错参考；不要把 `why-server` / `computing` 作为 CI 运行目标。 |

构建上下文排除项在仓库根的 `.dockerignore`，用于减少 Docker build 上下文。

---

## 7. 数据安全边界

- 禁止在 `why-server` / host `computing` 上运行任何 CI/test 命令、compose 命令、pytest 命令或测试容器。
- CI 只能使用本地或非生产服务器上的一次性 MySQL/Redis；不得连接生产 MySQL/Redis。
- CI 配置必须来自 `tests/ci/config.ci.py` 或等价的测试配置；不得读取、挂载、复制、合并生产 `config.py`。
- `down -v` 会删除测试数据卷；只允许对明确的测试 compose project 使用。
- 如果无法证明当前主机、目录、数据库和 Redis 都不是生产环境，停止运行并先确认。

---

## 8. 排错

- mysql 未就绪 / 连不上：`test` 依赖 `mysql: condition: service_healthy`，正常会等。仍报连不上就看日志：
  ```bash
  docker compose -f tests/ci/docker-compose.local.yml logs mysql
  ```
- schema 未灌入 / 改了 `myojdb.sql` 不生效：`myojdb.sql` 只在 mysql 数据卷首次初始化时执行；卷里有旧数据就不会重灌。用下面命令删卷后重跑：
  ```bash
  docker compose -f tests/ci/docker-compose.local.yml down -v --remove-orphans
  ```
- 判题用例失败（找不到 octave/gcc）：改了 `Dockerfile` 后要 `up --build` 重建镜像。
- `PIP_BREAK_SYSTEM_PACKAGES`：进容器手动 pip 时需带它，或使用 `pip3 install --break-system-packages`。
- 进容器手动调试：
  ```bash
  docker compose -f tests/ci/docker-compose.local.yml run --rm test bash
  # 容器内: python3 -m pytest tests/... -v、查 /app/config.py、连 mysql/redis
  ```
