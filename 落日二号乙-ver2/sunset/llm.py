"""最小 OpenAI-compatible LLM 客户端。

只做一件事：一次 system+user 调用，要求返回 JSON。没有工具、没有循环、没有
函数调用协议——这正是「工具调用种类更少甚至没有」的落点。
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from .config import Settings
from .security.guard import redact_secrets, sanitize_model_text


@dataclass
class LlmResult:
    ok: bool
    data: dict[str, Any] = field(default_factory=dict)
    raw: str = ""
    error: str = ""
    usage: dict[str, Any] = field(default_factory=dict)


def extract_json(text: str) -> dict[str, Any] | None:
    if not text:
        return None
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    candidate = text[start:end + 1]
    for attempt in (candidate, candidate.replace(",}", "}").replace(",]", "]")):
        try:
            value = json.loads(attempt)
            return value if isinstance(value, dict) else None
        except json.JSONDecodeError:
            continue
    return None


class LlmClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.usage: list[dict[str, Any]] = []
        self.last_error = ""

    @property
    def available(self) -> bool:
        return self.settings.llm_enabled

    def _endpoint(self) -> str:
        base = (self.settings.llm_base_url or "").rstrip("/")
        if base.endswith("/chat/completions"):
            return base
        return base + "/chat/completions"

    def call_json(self, system: str, user: str, *, label: str = "agent") -> LlmResult:
        if not self.available:
            return LlmResult(ok=False, error="LLM 未启用")
        system = system[:24000]
        user = user[:48000]
        payload = {
            "model": self.settings.llm_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.settings.llm_temperature,
            "max_tokens": self.settings.llm_max_tokens,
            "response_format": {"type": "json_object"},
        }
        last_error = ""
        for attempt in range(4):
            body = dict(payload)
            if attempt > 0:
                body.pop("response_format", None)
            request = urllib.request.Request(
                self._endpoint(),
                data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.settings.llm_api_key}",
                    "Accept": "application/json",
                },
                method="POST",
            )
            started = time.time()
            try:
                with urllib.request.urlopen(request, timeout=self.settings.llm_timeout) as response:
                    raw_bytes = response.read()
                raw = raw_bytes.decode("utf-8", errors="replace")
                parsed = json.loads(raw)
                content = ""
                choices = parsed.get("choices") or []
                if choices:
                    content = (choices[0].get("message") or {}).get("content") or ""
                usage = parsed.get("usage") or {}
                record = {
                    "agent": label,
                    "model": self.settings.llm_model,
                    "duration_sec": round(time.time() - started, 2),
                    "usage": usage,
                    "ok": True,
                }
                self.usage.append(record)
                data = extract_json(content)
                if data is None:
                    self.last_error = "模型返回内容不是有效 JSON"
                    return LlmResult(ok=False, raw=content[:2000], error=self.last_error, usage=usage)
                return LlmResult(ok=True, data=data, raw=content[:2000], usage=usage)
            except urllib.error.HTTPError as exc:
                detail = ""
                try:
                    detail = exc.read().decode("utf-8", errors="replace")[:800]
                except Exception:  # noqa: BLE001
                    pass
                last_error = f"HTTP {exc.code}: {redact_secrets(detail)}"
                self.usage.append({"agent": label, "ok": False, "error": last_error,
                                   "duration_sec": round(time.time() - started, 2)})
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last_error = redact_secrets(str(exc))[:500]
                self.usage.append({"agent": label, "ok": False, "error": last_error,
                                   "duration_sec": round(time.time() - started, 2)})
            except Exception as exc:  # noqa: BLE001 - 网络层异常（RemoteDisconnected/Reset）也必须重试而非中断管线
                last_error = f"{type(exc).__name__}: {redact_secrets(str(exc))[:400]}"
                self.usage.append({"agent": label, "ok": False, "error": last_error,
                                   "duration_sec": round(time.time() - started, 2)})
            if attempt < 3:
                time.sleep(1.5 * (attempt + 1))
        self.last_error = last_error
        return LlmResult(ok=False, error=last_error)


def system_with_policy(policy: str, agent_prompt: str) -> str:
    """把全局安全策略放在每个 agent 的最前面。"""
    return f"{policy.strip()}\n\n---\n\n{agent_prompt.strip()}\n"


def sanitize_for_prompt(text: str, max_chars: int = 8000) -> str:
    return sanitize_model_text(text, max_chars=max_chars)
