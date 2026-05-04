import functools
import threading
from types import SimpleNamespace

import anthropic
import httpx as _httpx
import ida_kernwin

from gepetto.models.base import LanguageModel
import gepetto.models.model_manager
import gepetto.config

_ = gepetto.config._

CLAUDE_OPUS_MODEL = "claude-opus-4-7"
CLAUDE_SONNET_MODEL = "claude-sonnet-4-6"
CLAUDE_HAIKU_MODEL = "claude-haiku-4-5"

_MAX_TOKENS = {
    CLAUDE_OPUS_MODEL: 16000,
    CLAUDE_SONNET_MODEL: 16000,
    CLAUDE_HAIKU_MODEL: 8192,
}


def _notify_stream_error(callback, message):
    if callback is None:
        return
    payload = SimpleNamespace(error=message)
    try:
        callback(payload, "error")
    except TypeError:
        callback(payload)


def _notify_non_stream_error(callback, message):
    if callback is None:
        return
    payload = SimpleNamespace(error=message)

    def _invoke():
        try:
            callback(payload)
        except TypeError:
            callback(payload, "error")

    ida_kernwin.execute_sync(_invoke, ida_kernwin.MFF_WRITE)


class Claude(LanguageModel):
    @staticmethod
    def get_menu_name():
        return "Anthropic"

    @staticmethod
    def supported_models():
        return [CLAUDE_OPUS_MODEL, CLAUDE_SONNET_MODEL, CLAUDE_HAIKU_MODEL]

    @staticmethod
    def is_configured_properly():
        return bool(gepetto.config.get_config("Claude", "API_KEY", "ANTHROPIC_API_KEY"))

    def __init__(self, model):
        self.model = model
        self.input_tokens = 0
        self.output_tokens = 0

        api_key = gepetto.config.get_config("Claude", "API_KEY", "ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                _("Please edit the configuration file to insert your {api_provider} API key!")
                .format(api_provider="Anthropic")
            )

        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        base_url = gepetto.config.get_config("Claude", "BASE_URL", "ANTHROPIC_BASE_URL")

        client_kwargs = {"api_key": api_key}
        if base_url:
            client_kwargs["base_url"] = base_url
        if proxy:
            client_kwargs["http_client"] = _httpx.Client(proxy=proxy)

        self.client = anthropic.Anthropic(**client_kwargs)

    def __str__(self):
        return self.model

    @staticmethod
    def _convert_query(query):
        """Convert a Gepetto query to Claude's (system, messages) format."""
        if isinstance(query, str):
            return None, [{"role": "user", "content": query}]

        system_parts = []
        messages = []
        for msg in query:
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role == "system":
                system_parts.append(str(content))
            elif role in ("user", "assistant"):
                messages.append({"role": role, "content": str(content)})

        if not messages:
            messages = [{"role": "user", "content": ""}]

        system = "\n".join(system_parts) if system_parts else None
        return system, messages

    def query_model(self, query, cb, stream=False, additional_model_options=None):
        if additional_model_options is None:
            additional_model_options = {}

        options = dict(additional_model_options)
        response_format = options.pop("response_format", None)
        options.pop("tools", None)
        options.pop("tool_choice", None)

        system_prompt, messages = self._convert_query(query)

        if isinstance(response_format, dict) and response_format.get("type") == "json_object":
            json_instruction = "You must respond with valid JSON only. No markdown, no code fences, no commentary."
            if system_prompt:
                system_prompt = f"{system_prompt}\n\n{json_instruction}"
            else:
                system_prompt = json_instruction

        max_tokens = _MAX_TOKENS.get(self.model, 16000)
        create_kwargs = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": messages,
        }
        if system_prompt:
            create_kwargs["system"] = system_prompt

        try:
            if not stream:
                response = self.client.messages.create(**create_kwargs)
                text = "".join(
                    block.text for block in response.content if block.type == "text"
                )
                message = SimpleNamespace(content=text)
                ida_kernwin.execute_sync(
                    functools.partial(cb, response=message),
                    ida_kernwin.MFF_WRITE,
                )
                self.input_tokens += response.usage.input_tokens
                self.output_tokens += response.usage.output_tokens
            else:
                with self.client.messages.stream(**create_kwargs) as stream_response:
                    for text in stream_response.text_stream:
                        cb(SimpleNamespace(content=text), None)

                    final = stream_response.get_final_message()
                    self.input_tokens += final.usage.input_tokens
                    self.output_tokens += final.usage.output_tokens

                stop_map = {
                    "end_turn": "stop",
                    "max_tokens": "length",
                    "tool_use": "tool_calls",
                }
                cb(None, stop_map.get(final.stop_reason, "stop"))

        except anthropic.BadRequestError as e:
            error_message = _(
                "General exception encountered while running the query: {error}"
            ).format(error=str(e))
            print(error_message)
            if stream:
                _notify_stream_error(cb, error_message)
            else:
                _notify_non_stream_error(cb, error_message)
        except anthropic.AuthenticationError:
            error_message = _(
                "Please edit the configuration file to insert your {api_provider} API key!"
            ).format(api_provider="Anthropic")
            print(error_message)
            if stream:
                _notify_stream_error(cb, error_message)
            else:
                _notify_non_stream_error(cb, error_message)
        except anthropic.APIError as e:
            error_message = _("{model} could not complete the request: {error}").format(
                model=self.model, error=str(e)
            )
            print(error_message)
            if stream:
                _notify_stream_error(cb, error_message)
            else:
                _notify_non_stream_error(cb, error_message)
        except Exception as e:
            error_message = _(
                "General exception encountered while running the query: {error}"
            ).format(error=str(e))
            print(error_message)
            if stream:
                _notify_stream_error(cb, error_message)
            else:
                _notify_non_stream_error(cb, error_message)

    def query_model_async(self, query, cb, stream=False, additional_model_options=None):
        t = threading.Thread(
            target=self.query_model,
            args=[query, cb, stream, additional_model_options],
            daemon=True,
        )
        t.start()


gepetto.models.model_manager.register_model(Claude)
