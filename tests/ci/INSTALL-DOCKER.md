# 在 why-server 安装 Docker（历史记录）

> 这是历史安装记录和 Docker 排错参考，不是 CI 运行说明。**CI/test 禁止在 `why-server` / host `computing` 上运行**；日常使用 CI 见同目录 [`README.md`](./README.md)，并只能在本地或非生产服务器运行。
>
> 这是在 why-server 上首次安装 Docker Engine + Compose 插件的完整、可复现命令序列。所有命令通过 `ssh why-server '...'` 在本机发起，远程用户为 `ebola`（可 sudo，但需密码）。下文中 sudo 密码一律以 `<sudo-password>` 表示。
>
> 该主机的 hostname 是 `computing`，但未写入 `/etc/hosts`，因此每次 sudo 都会打印一行无害告警：`sudo: unable to resolve host computing: Name or service not known`。**忽略它**，sudo 仍然正常工作。

安装时的机器规格：Debian GNU/Linux 12 (bookworm)，内核 6.1.0-28-amd64，x86_64，40 核 / 125 GiB，已启用 user namespaces。安装前确认无 `docker` 二进制、无 `docker.service`。

## 实际执行的命令（按顺序）

```bash
# 0) 验证 SSH 与 sudo 可用（返回 root 即正常；忽略 hostname 告警）
ssh why-server 'echo "<sudo-password>" | sudo -S whoami'

# 1) （可选）把 hostname 写入 /etc/hosts，消除每次 sudo 的 hostname 告警
ssh why-server 'echo "<sudo-password>" | sudo -S bash -c "grep -q computing /etc/hosts || echo \"127.0.1.1 computing\" >> /etc/hosts"'

# 2) 下载 Docker 官方便捷安装脚本（不加 sudo；写到文件，让密码留在 stdin 给后续 sudo -S）
ssh why-server 'curl -fsSL https://get.docker.com -o /tmp/get-docker.sh'

# 3) 让 APT 强制走 IPv4（关键，见“踩坑记录”）
ssh why-server 'echo "<sudo-password>" | sudo -S bash -c "echo \"Acquire::ForceIPv4 \\\"true\\\";\" > /etc/apt/apt.conf.d/99force-ipv4"'

# 4) 安装 Docker Engine + CLI + containerd + buildx + compose 插件
#    （便捷脚本已配置好 docker.list 仓库与 keyring；强制 IPv4 后直接 apt 安装更稳）
ssh why-server 'echo "<sudo-password>" | sudo -S apt-get update'
ssh why-server 'echo "<sudo-password>" | sudo -S DEBIAN_FRONTEND=noninteractive apt-get install -y \
    docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin'
# 注：也可直接重跑 `echo "<sudo-password>" | sudo -S sh /tmp/get-docker.sh`，
#     强制 IPv4 后该脚本同样能装好。

# 5) 开机自启并立即启动 docker 服务
ssh why-server 'echo "<sudo-password>" | sudo -S systemctl enable --now docker'

# 6) 让 ebola 免 sudo 跑 docker
ssh why-server 'echo "<sudo-password>" | sudo -S usermod -aG docker ebola'

# 7) 配置镜像加速（关键，见“踩坑记录”——本机无法直连 Docker Hub registry）
ssh why-server 'echo "<sudo-password>" | sudo -S bash -c "cat > /etc/docker/daemon.json <<JSON
{
  \"registry-mirrors\": [\"https://docker.m.daocloud.io\"]
}
JSON"'
ssh why-server 'echo "<sudo-password>" | sudo -S systemctl restart docker'
```

## 验证（每次 ssh 都是全新会话，docker 组成员身份会自动生效）

```bash
ssh why-server 'docker --version && docker compose version && systemctl is-active docker'
ssh why-server 'id'                       # 应包含 docker 组
ssh why-server 'docker run --rm hello-world'   # 应成功，且无需 sudo
```

实测输出：

```
Docker version 29.5.2, build 79eb04c
Docker Compose version v5.1.4
active
# systemctl is-enabled docker -> enabled
# id -> uid=1004(ebola) gid=1004(ebola) groups=1004(ebola),992(docker),995(ollama)
# docker run --rm hello-world -> "Hello from Docker! ..." 退出码 0
```

安装组件版本：Docker CE **29.5.2**、Compose 插件 **v5.1.4**、containerd.io **2.2.4**、buildx **0.34.1**。Storage Driver 为 `overlayfs`。

## 踩坑记录

1. **sudo 的 hostname 告警**：每次 sudo 都打印 `sudo: unable to resolve host computing: Name or service not known`。无害，sudo 照常工作。可选地用上面的步骤 1 把 `127.0.1.1 computing` 写入 `/etc/hosts` 消除。

2. **`sudo -S` 会吃掉 stdin**：不能直接 `cat script | sudo -S sh`（密码与脚本抢 stdin）。正确做法是先 `curl ... -o /tmp/get-docker.sh`（不加 sudo），再 `echo '<sudo-password>' | sudo -S sh /tmp/get-docker.sh`——脚本从文件参数读取，密码独占 stdin。

3. **APT 走 IPv6 导致 TLS 握手失败（核心坑）**：首跑便捷脚本时，`apt-get update` 与下载 `.deb` 都报
   `Could not handshake: Error in the pull function. [IP: 2600:9000:...]`，
   最终 `E: Package 'docker-ce' has no installation candidate` / `Unable to fetch some archives`。
   原因：`download.docker.com` 的 CDN 在本机解析到 IPv6，APT 优先用 IPv6，而本机到该 CDN 的 IPv6 路径 TLS 握手不稳定/失败（用 `curl -4` 测同一 URL 反而 200）。
   **解决**：写 `/etc/apt/apt.conf.d/99force-ipv4`，内容 `Acquire::ForceIPv4 "true";`，强制 APT 走 IPv4，之后 `apt-get update` 与安装全部成功。

4. **无关仓库的 GPG 过期告警**：安装过程中一直有
   `GPG error: ... repo.mysql.com ... EXPKEYSIG B7B3B788A8D3785C` 与 `apt.v2raya.org ... EXPKEYSIG 354E516D494EF95F`。
   这是该主机上**已有的、与 Docker 无关**的第三方源（MySQL / v2raya）签名过期。它们只是 warning（`They have been ignored, or old ones used instead`），不影响 Docker 安装，未做处理。

5. **docker 组成员身份是否需要重新登录**：本场景**不需要**。`usermod -aG docker ebola` 之后，由于每个 `ssh why-server '...'` 都是全新登录会话，新会话天然带上 `docker` 组（`id` 已含 `992(docker)`），`docker run` 无需 sudo 即成功。
   **若是在同一个已登录的交互 shell 里加的组**，则当前 shell 不会立即生效，需要重新登录，或临时用 `sg docker -c "docker ..."` / `newgrp docker` 兜底。

6. **无法直连 Docker Hub registry（核心坑）**：`docker run --rm hello-world` 第一次失败：
   `dial tcp [2a03:2880:...]:443: i/o timeout`。
   注意此时 daemon 已正常响应（**不是**权限/组错误，说明免 sudo 已生效），只是拉镜像超时。
   排查发现 `registry-1.docker.io` 在本机只解析出 IPv6 地址，且 IPv4/IPv6 直连 `https://registry-1.docker.io/v2/` 均超时——本机无法直连 Docker Hub。
   逐个探测镜像源，只有 `https://docker.m.daocloud.io/v2/` 返回 401（正常的“需鉴权”，即可达），其余（dockerproxy / 网易 / 腾讯 / ustc 等）均超时。
   **解决**：在 `/etc/docker/daemon.json` 配置 `registry-mirrors: ["https://docker.m.daocloud.io"]`，`systemctl restart docker` 后 `hello-world` 拉取成功。
   > 历史影响：当时 CI 镜像用到的 `mysql:8.0`、`redis:7`、`debian:12-slim` 等基础镜像也会经由该镜像源拉取。该记录不表示现在允许在 `why-server` 上运行 CI/test。

7. **构建镜像时 apt / pip 同样走 IPv6 会失败**：`tests/ci/Dockerfile` 内构建测试镜像时，`apt-get`（装 octave 等）与 `pip3 install`（装 faiss 等）也会遇到同样的国际源 IPv6 问题。Dockerfile 已内置应对：强制 apt 走 IPv4 + 切清华 Debian 镜像、`pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple`。换主机时若网络环境不同，可相应调整。
