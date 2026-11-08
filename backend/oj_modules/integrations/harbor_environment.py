"""通过官方扩展接口给作答与独立验证环境追加平台容器约束。"""

import json
import math
import os
from pathlib import Path
import subprocess
import stat

from harbor.environments.docker.docker import DockerEnvironment
from backend.oj_modules.ranking.reverse_judge.template import DEFAULT_HARBOR_DOCKERFILE


class PlatformDockerEnvironment(DockerEnvironment):
    def __init__(self, *args, platform_overlay, platform_cache_path=None, platform_event_path=None,
                 extra_docker_compose=None, **kwargs):
        overlay = Path(platform_overlay)
        if not overlay.is_absolute() or overlay.is_symlink() or not overlay.is_file():
            raise ValueError("Harbor 平台容器配置不存在或无效")
        paths = [Path(path) for path in extra_docker_compose or []]
        if overlay not in paths:
            paths.append(overlay)
        environment_dir = Path(kwargs["environment_dir"]).resolve()
        task_config = kwargs["task_env_config"].model_copy(deep=True)
        for option, field, default in (("override_cpus", "cpus", 2),
                                       ("override_memory_mb", "memory_mb", 4096)):
            declared = getattr(task_config, field)
            if declared is not None and (
                declared <= 0 or isinstance(declared, float) and not math.isfinite(declared)
            ):
                # Docker 的 0 表示不设限制，不能把学生声明的 0 透传为无限资源。
                raise ValueError(f"Harbor {field} 必须是大于 0 的有限数值")
            ceiling = kwargs.get(option)
            ceiling = default if ceiling is None else min(ceiling, default)
            kwargs[option] = min(declared, ceiling) if declared is not None else ceiling
            if field == "cpus" and kwargs[option] < 0.01:
                # 极小 CPU 值在 Compose/Docker 换算为整数配额时可能归零。
                raise ValueError("Harbor cpus 至少为 0.01，不能低于 Docker 可表达的安全配额")
        # 通用评测容器使用 CPU；不能由学生配置申请宿主 GPU。
        kwargs["override_gpus"] = 0
        task_config.env.update(NVIDIA_VISIBLE_DEVICES="void", CUDA_VISIBLE_DEVICES="")
        self._platform_cache_path = Path(platform_cache_path) if platform_cache_path else None
        self._platform_event_path = Path(platform_event_path) if platform_event_path else None
        self._platform_agent_environment = str(kwargs.get('session_id') or '').endswith('__env')
        self._platform_source_dir = str(environment_dir)
        self.numoj_cache_hit = False
        dockerfile = environment_dir / "Dockerfile"
        expected = DEFAULT_HARBOR_DOCKERFILE.encode("utf-8")
        is_default = False
        if dockerfile.is_file():
            with dockerfile.open("rb") as stream:
                is_default = stream.read(len(expected) + 1) == expected
        custom_default = (dockerfile.is_file() and not is_default
                          and task_config.docker_image == "numericaloj-harbor-base:1")
        if is_default and task_config.docker_image in (None, "numericaloj-harbor-base:1"):
            task_config.docker_image = "numericaloj-harbor-base:1"
            task_config.workdir = task_config.workdir or "/app"
        elif custom_default:
            # 用户修改默认Dockerfile后，官方预构建开关必须让位于新的环境定义。
            task_config.docker_image = None
        if self._platform_cache_path and self._platform_cache_path.exists():
            if self._platform_cache_path.is_symlink() or self._platform_cache_path.stat().st_size > 65536:
                raise ValueError("Harbor 构建缓存记录无效")
            cache = json.loads(self._platform_cache_path.read_text(encoding="utf-8"))
            image = (cache.get("environments") or {}).get(self._platform_source_dir)
            if image and self._image_available(image):
                task_config.docker_image = image
                self.numoj_cache_hit = True
        if task_config.docker_image and self._image_available(task_config.docker_image):
            self.numoj_cache_hit = True
        kwargs["task_env_config"] = task_config
        super().__init__(*args, extra_docker_compose=paths, **kwargs)
        if not self.task_env_config.docker_image and self._image_available(self._main_image_name):
            # 镜像名及缓存身份完全由Harbor官方环境定义；只复用已存在的
            # 官方构建结果，不新增平台指纹或文件版本校验。
            self.task_env_config.docker_image = self._main_image_name
            self._env_vars.prebuilt_image_name = self._main_image_name
            self.numoj_cache_hit = True

    @classmethod
    def _image_available(cls, image):
        result = subprocess.run(cls._engine_cmd("image", "inspect", str(image)),
                                capture_output=True, timeout=20, check=False)
        return result.returncode == 0

    async def start(self, force_build):
        self._build_event('start', cached=self.numoj_cache_hit,
                          text='复用已有 Harbor 环境镜像。\n' if self.numoj_cache_hit else '开始构建 Harbor 任务环境。\n')
        async def output(text, stream):
            self._build_event('output', stream=getattr(stream, 'value', str(stream)), text=text)
        with self.scoped_output_callback(output):
            await super().start(force_build=force_build)
        if self._platform_cache_path:
            path = self._platform_cache_path
            cache = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"environments": {}}
            cache.setdefault("environments", {})[self._platform_source_dir] = (
                self.task_env_config.docker_image if self._use_prebuilt else self._main_image_name
            )
            temporary = path.with_suffix(".tmp")
            with temporary.open("w", encoding="utf-8") as stream:
                os.chmod(temporary, 0o600)
                json.dump(cache, stream)
            temporary.replace(path)
        self._build_event('complete', cached=self.numoj_cache_hit, text='Harbor 环境已就绪。\n')

    def _build_event(self, event, **fields):
        """仅宿主扩展能写入此私有通道；容器 stdout 不是控制协议。"""
        if not self._platform_agent_environment or self._platform_event_path is None:
            return
        descriptor = os.open(self._platform_event_path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'a', encoding='utf-8') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise ValueError('Harbor 构建事件通道无效')
            # 终态事件必须送达；大量 build 输出只用于有上限的终端预览。
            if event == 'output' and metadata.st_size > 32 * 1024 * 1024:
                return
            if 'text' in fields:
                fields['text'] = str(fields['text'])[:65536]
            stream.write(json.dumps({'type': 'build', 'event': event, **fields}, ensure_ascii=False) + '\n')

    async def _run_docker_compose_command(self, command, check=True, timeout_sec=None,
                                           stdin_data=None, on_output=None):
        if command[:1] == ["down"] and "--rmi" in command:
            # 官方默认清理会删除本地任务镜像；平台需保留官方缓存供后续
            # 提交复用。容器、卷与孤儿容器仍按原命令完整删除。
            command = list(command)
            index = command.index("--rmi")
            del command[index:index + 2]
        # 上游start()调用compose build时默认缓冲输出；沿用官方执行方法，
        # 只接入其已提供的流式回调，向第0步实时发布构建终端日志。
        if command[:1] == ["build"] and on_output is None:
            on_output = self._output_callback()
        return await super()._run_docker_compose_command(
            command, check=check, timeout_sec=timeout_sec, stdin_data=stdin_data, on_output=on_output,
        )
