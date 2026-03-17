"""Anthropic provider adapter."""
import anthropic
from core.providers.base import BaseProvider, ProviderResponse


class AnthropicProvider(BaseProvider):
    def __init__(self, api_key: str, model: str):
        super().__init__(api_key, model)
        self.client = anthropic.Anthropic(api_key=api_key)

    def complete(self, system_prompt: str, user_message: str) -> ProviderResponse:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=system_prompt,
            messages=[
                {"role": "user", "content": user_message},
            ],
        )
        content = response.content[0].text if response.content else ""
        tokens = response.usage.input_tokens + response.usage.output_tokens
        return ProviderResponse(
            content=content,
            tokens_used=tokens,
            model=self.model,
        )
