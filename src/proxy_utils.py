"""Proxy parsing and Chrome launch-arg helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import unquote, urlsplit, urlunsplit


class ProxyConfigError(ValueError):
    """Raised when a proxy URL cannot be parsed safely."""


@dataclass(frozen=True)
class ProxyConfig:
    """Parsed proxy configuration."""

    server: str
    username: Optional[str] = None
    password: Optional[str] = None


def _format_host(hostname: str) -> str:
    if ":" in hostname and not hostname.startswith("["):
        return f"[{hostname}]"
    return hostname


def parse_proxy_config(proxy_url: str) -> ProxyConfig:
    """Parse a proxy URL into a Chrome-compatible server string + credentials."""

    if not isinstance(proxy_url, str) or not proxy_url.strip():
        raise ProxyConfigError("Proxy URL is empty")

    raw = proxy_url.strip()
    value = raw if "://" in raw else f"http://{raw}"

    try:
        parsed = urlsplit(value)
    except Exception as error:
        raise ProxyConfigError(f"Invalid proxy URL: {raw}") from error

    hostname = parsed.hostname
    if not hostname:
        raise ProxyConfigError(f"Invalid proxy URL (missing hostname): {raw}")

    host = _format_host(hostname)
    netloc = host
    try:
        port = parsed.port
    except ValueError as error:
        raise ProxyConfigError(f"Invalid proxy URL (bad port): {raw}") from error
    if port is not None:
        netloc = f"{host}:{port}"

    scheme = parsed.scheme or "http"
    server = urlunsplit((scheme, netloc, "", "", ""))

    return ProxyConfig(
        server=server,
        username=unquote(parsed.username) if parsed.username else None,
        password=unquote(parsed.password) if parsed.password is not None else None,
    )


def merge_proxy_server_arg(args: List[str], proxy_server: Optional[str]) -> List[str]:
    """Ensure args contain exactly one --proxy-server=... entry."""

    if not proxy_server:
        return args
    prefix = "--proxy-server="
    merged: List[str] = []
    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg.startswith(prefix):
            idx += 1
            continue
        if arg == "--proxy-server":
            idx += 2
            continue
        merged.append(arg)
        idx += 1

    merged.append(f"{prefix}{proxy_server}")
    return merged


def redact_launch_arg(arg: str) -> str:
    """Redact any userinfo embedded in URL-ish launch args (best-effort)."""

    if not isinstance(arg, str):
        return str(arg)

    prefix = "--proxy-server="
    if arg.startswith(prefix):
        value = arg[len(prefix) :]
        try:
            parsed = urlsplit(value if "://" in value else f"http://{value}")
            if parsed.username or parsed.password:
                hostname = parsed.hostname or ""
                host = _format_host(hostname)
                netloc = host
                if parsed.port is not None:
                    netloc = f"{host}:{parsed.port}"
                sanitized = urlunsplit(
                    (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
                )
                return f"{prefix}{sanitized}"
        except Exception:
            return prefix + "<redacted>"

    if "://" in arg and "@" in arg:
        try:
            parsed = urlsplit(arg)
            if parsed.username or parsed.password:
                hostname = parsed.hostname or ""
                host = _format_host(hostname)
                netloc = host
                if parsed.port is not None:
                    netloc = f"{host}:{parsed.port}"
                return urlunsplit(
                    (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
                )
        except Exception:
            return "<redacted>"

    return arg
