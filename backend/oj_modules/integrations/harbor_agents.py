"""官方已安装 Agent 的镜像安装缓存与模型能力适配；执行协议完全继承上游。"""

import re

from pydantic import Field
from harbor.agents.installed.claude_code import ClaudeCode
from harbor.agents.installed.codex import Codex
from harbor.agents.installed.opencode import OpenCode
from harbor.agents.installed.pi import Pi, PiOptions


class _CachedInstallation:
    async def install(self, environment):
        binary = 'claude' if self.name() == 'claude-code' else self.name()
        result = await environment.exec(f'command -v {binary} >/dev/null && {binary} --version', timeout_sec=20)
        version = self.version()
        if (version and result.return_code == 0
                and re.search(r'(?<![\d.])' + re.escape(version) + r'(?![\d.])', result.stdout or '')):
            return
        await super().install(environment)


class CachedClaudeCode(_CachedInstallation, ClaudeCode):
    pass


class CachedCodex(_CachedInstallation, Codex):
    pass


class CachedOpenCode(_CachedInstallation, OpenCode):
    pass


class EndpointPiOptions(PiOptions):
    context_window_tokens: int | None = Field(default=None, gt=0)
    max_output_tokens: int | None = Field(default=None, gt=0)


class CachedPi(_CachedInstallation, Pi):
    # 上游 0.25 未公开这两个字段，也不支持 native_config；只扩展其 provider 配置。
    options_model = EndpointPiOptions
    options: EndpointPiOptions

    def _build_custom_models_json(self, *args, **kwargs):
        models = super()._build_custom_models_json(*args, **kwargs)
        if models:
            for provider in models.get('providers', {}).values():
                for model in provider.get('models', []):
                    for source, target in (('context_window_tokens', 'contextWindow'), ('max_output_tokens', 'maxTokens')):
                        value = getattr(self.options, source)
                        if value is not None:
                            model[target] = value
        return models
