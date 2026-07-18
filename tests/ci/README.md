# NumericalOJ Docker CI

本目录是 NumericalOJ 的容器化测试配置：在 **独立 MySQL + Redis + 真实判题工具链（gcc/g++/python3/octave）** 的隔离环境中逐模块跑 pytest。端到端验证统一走 `tests/e2e/`：先启动本地 Flask 服务，再通过 `numoj-admin` / `numoj-user` CLI 操作真实 HTTP 路由；测试按 auth、problem/submission、homework/class、repository/forum、ranking、AI detection 和 help matrix 分类拆分。

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

它会构建测试镜像，启动独立的 `mysql` / `redis` 容器，等待服务 healthy 后运行 `tests/ci/run-ci.sh`，最后把 JUnit XML 写到本机 `./test-results/`。Compose 显式注入 `NUMOJ_TEST_ENV=1`；测试配置固定使用 MySQL `myojdb_test` 和 Redis DB 15，安全门会在任何清理动作前再次校验。

清理测试容器和数据卷：

```bash
docker compose -f tests/ci/docker-compose.local.yml down -v --remove-orphans
```

---

## 3. 非生产服务器运行

如果本机资源不足，可以把 CI 跑在另一台明确的非生产服务器上。禁止使用 `why-server` / host `computing`。

不要使用仓库脚本自动同步并远程运行测试；这类脚本容易被误指向生产主机。需要在非生产服务器上跑时，手动把代码放到该服务器的独立目录，然后在那台服务器本地执行：

```bash
docker compose -f tests/ci/docker-compose.local.yml up --build --abort-on-container-exit --exit-code-from test
```

跑完后在同一目录清理测试容器和数据卷：

```bash
docker compose -f tests/ci/docker-compose.local.yml down -v --remove-orphans
```

---

## 4. 只跑单个模块 / 单个用例

CI 已 `up --build` 至少一次后，可在同一台本地或非生产服务器上只跑某个文件：

```bash
docker compose -f tests/ci/docker-compose.local.yml run --rm test \
    python3 -m pytest tests/e2e -v

docker compose -f tests/ci/docker-compose.local.yml run --rm test \
    python3 -m pytest tests/e2e/test_ranking_cli.py::test_ranking_agent_judge_git_check_submit_and_batch_admin -v
```

把路径换成 `tests/unit`、`tests/db` 等即可。仍然禁止在 `why-server` / host `computing` 上执行这些命令。

---

## 5. 看结果

- 终端汇总表：`run-ci.sh` 结尾按模块打印：
  ```text
  =================== 汇总 ===================
  tests/unit                                    PASS
  tests/db                                      PASS
  tests/e2e                                     PASS
  ...
  ===========================================
  ```
- JUnit XML：每个模块一份 `test-results/<模块路径转义>.xml`，可喂给任意 JUnit 报告工具。

---

## 6. 目录布局（`tests/ci/`）

| 文件 | 职责 |
| --- | --- |
| `Dockerfile` | 基于 `python:3.12-slim-bookworm` 构建测试镜像：安装 `gcc/g++/build-essential`、`octave`、`coreutils`、`default-mysql-client`、`ca-certificates` 和 Python 依赖；构建时校验 Python/pip 基线，并用 `config.ci.py` 覆盖 `/app/config.py`。 |
| `docker-compose.local.yml` | 推荐的本地/非生产 CI compose 文件；编排独立 `mysql`、`redis`、`test`，不挂载生产路径。 |
| `docker-compose.ci.yml` | 历史主机专用 compose 文件，包含宿主 MKL 挂载；日常 CI 优先使用 `docker-compose.local.yml`，且任何 compose 文件都不能在 `why-server` / host `computing` 上运行。 |
| `config.ci.py` | 自包含 CI 配置。MySQL/Redis 指向 compose 服务名 `mysql`/`redis`，使用 `myojdb_test` / Redis DB 15；AI/SMTP 使用测试占位值，测试中网络 AI 通常 mock 或 skip。 |
| `run-ci.sh` | 在 `test` 容器内逐模块顺序跑 pytest（unit -> db -> CLI e2e），逐模块打印结果并写 JUnit XML；任一模块失败则整体非零退出。 |
| `INSTALL-DOCKER.md` | Docker 安装记录和排错参考；不要把 `why-server` / `computing` 作为 CI 运行目标。 |

构建上下文排除项在仓库根的 `.dockerignore`，用于减少 Docker build 上下文。

---

## 7. 数据安全边界

- 禁止在 `why-server` / host `computing` 上运行任何 CI/test 命令、compose 命令、pytest 命令或测试容器。
- CI 只能使用本地或非生产服务器上的一次性 MySQL/Redis；不得连接生产 MySQL/Redis。
- CI 配置必须来自 `tests/ci/config.ci.py` 或等价的测试配置；不得读取、挂载、复制、合并生产 `config.py`。
- 不得删除或绕过 `NUMOJ_TEST_ENV=1`、专用测试库、非零 Redis DB、主机和路径的 fail-closed 校验。
- `down -v` 会删除测试数据卷；只允许对明确的测试 compose project 使用。
- 如果无法证明当前主机、目录、数据库和 Redis 都不是生产环境，停止运行并先确认。

---

## 8. 排错

- mysql 未就绪 / 连不上：`test` 依赖 `mysql: condition: service_healthy`，正常会等。仍报连不上就看日志：
  ```bash
  docker compose -f tests/ci/docker-compose.local.yml logs mysql
  ```
- 报“拒绝执行可能清空 MySQL/Redis 的测试”：先检查 test 容器中 `NUMOJ_TEST_ENV=1`、`MYSQL_DB='myojdb_test'` 和 `REDIS_DB=15`，不要通过放宽 `tests/environment_guard.py` 绕过。
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
