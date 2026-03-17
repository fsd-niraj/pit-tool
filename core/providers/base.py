"""Abstract provider interface."""
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ProviderResponse:
    content: str
    tokens_used: int
    model: str


class BaseProvider(ABC):
    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model

    @abstractmethod
    def complete(self, system_prompt: str, user_message: str) -> ProviderResponse:
        pass

    @classmethod
    def create(cls, provider: str, api_key: str, model: str) -> "BaseProvider":
        from core.providers.openai_provider import OpenAIProvider
        from core.providers.anthropic_provider import AnthropicProvider

        registry: dict[str, type[BaseProvider]] = {
            "openai": OpenAIProvider,
            "anthropic": AnthropicProvider,
        }

        if provider not in registry:
            supported = list(registry.keys())
            raise ValueError(f"Unknown provider '{provider}'. Supported: {supported}")

        return registry[provider](api_key=api_key, model=model)
