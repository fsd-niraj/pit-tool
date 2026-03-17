"""OpenAI provider adapter."""
from openai import OpenAI
from core.providers.base import BaseProvider, ProviderResponse


class OpenAIProvider(BaseProvider):
    def __init__(self, api_key: str, model: str):
        super().__init__(api_key, model)
        self.client = OpenAI(api_key=api_key)

    def complete(self, system_prompt: str, user_message: str) -> ProviderResponse:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        )
        return ProviderResponse(
            content=response.choices[0].message.content or "",
            tokens_used=response.usage.total_tokens if response.usage else 0,
            model=self.model,
        )
