"""ZenProxy proxy-pool provider.

Fetches proxies from a ZenProxy Server instance and feeds them into the
existing proxy-pool infrastructure.  Supports two strategies:

* **direct**  – fetch HTTP / SOCKS proxies and use them as-is (curl_cffi native)
* **relay**   – forward requests through ZenProxy's ``/api/relay`` endpoint
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode

from app.platform.logging.logger import logger
from app.platform.config.snapshot import get_config

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ZenProxyNode:
    """A single proxy entry returned by ZenProxy."""

    proxy_id: str
    name: str = ""
    proxy_type: str = ""  # vmess, vless, trojan, shadowsocks, hysteria2, socks5, http, https
    server: str = ""
    port: int = 0
    local_port: int = 0  # sing-box binding port on ZenProxy server (server mode only)
    country: str = ""
    chatgpt: bool = False
    google: bool = False
    is_residential: bool = False
    risk_score: float = 0.0
    risk_level: str = "Unknown"
    outbound: dict[str, Any] = field(default_factory=dict)

    @property
    def is_direct_usable(self) -> bool:
        """Return True if curl_cffi can use this proxy natively."""
        return self.proxy_type in ("http", "https", "socks5", "socks4")

    @property
    def proxy_url(self) -> str | None:
        """Construct a ``proxy_url`` that curl_cffi understands, if possible."""
        if not self.server or not self.port:
            return None
        if self.proxy_type in ("http", "https"):
            return f"http://{self.server}:{self.port}"
        if self.proxy_type == "socks5":
            return f"socks5h://{self.server}:{self.port}"
        if self.proxy_type == "socks4":
            return f"socks4a://{self.server}:{self.port}"
        if self.local_port:
            # Server-mode: proxy is bound to a local port on the ZenProxy host.
            # Use the ZenProxy server's hostname as the proxy host.
            return f"http://{self.server}:{self.local_port}"
        return None


@dataclass
class ZenProxyFetchResult:
    proxies: list[ZenProxyNode] = field(default_factory=list)
    total: int = 0
    error: str = ""


# ---------------------------------------------------------------------------
# ZenProxy API client
# ---------------------------------------------------------------------------

_DIRECT_USABLE_TYPES = frozenset({"http", "https", "socks5", "socks4"})


class ZenProxyClient:
    """Async client for the ZenProxy Server API."""

    def __init__(
        self,
        server: str,
        api_key: str,
        timeout_sec: int = 30,
    ) -> None:
        self._server = server.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout_sec

    # -- /api/fetch ----------------------------------------------------------

    async def fetch(
        self,
        *,
        count: int = 50,
        country: str = "",
        proxy_type: str = "",
        chatgpt: bool = False,
        google: bool = False,
        residential: bool = False,
        risk_max: float = 0.0,
    ) -> ZenProxyFetchResult:
        """Fetch proxies from ``GET /api/fetch``."""
        params: dict[str, Any] = {
            "api_key": self._api_key,
            "count": count,
        }
        if country:
            params["country"] = country
        if proxy_type:
            params["type"] = proxy_type
        if chatgpt:
            params["chatgpt"] = "true"
        if google:
            params["google"] = "true"
        if residential:
            params["residential"] = "true"
        if risk_max > 0:
            params["risk_max"] = str(risk_max)

        url = f"{self._server}/api/fetch?{urlencode(params)}"
        return await self._get(url)

    # -- /api/client/fetch ---------------------------------------------------

    async def client_fetch(
        self,
        *,
        count: int = 50,
        country: str = "",
        proxy_type: str = "",
        chatgpt: bool = False,
        google: bool = False,
        residential: bool = False,
        risk_max: float = 0.0,
    ) -> ZenProxyFetchResult:
        """Fetch proxies from ``GET /api/client/fetch`` (includes outbound config)."""
        params: dict[str, Any] = {
            "api_key": self._api_key,
            "count": count,
        }
        if country:
            params["country"] = country
        if proxy_type:
            params["type"] = proxy_type
        if chatgpt:
            params["chatgpt"] = "true"
        if google:
            params["google"] = "true"
        if residential:
            params["residential"] = "true"
        if risk_max > 0:
            params["risk_max"] = str(risk_max)

        url = f"{self._server}/api/client/fetch?{urlencode(params)}"
        return await self._get(url)

    # -- /api/proxies (paginated) --------------------------------------------

    async def list_proxies(
        self,
        *,
        page: int = 1,
        per_page: int = 50,
        status: str = "valid",
        proxy_type: str = "",
    ) -> ZenProxyFetchResult:
        """Fetch paginated proxy list from ``GET /api/proxies``."""
        params: dict[str, Any] = {
            "api_key": self._api_key,
            "page": page,
            "per_page": min(per_page, 500),
        }
        if status:
            params["status"] = status
        if proxy_type:
            params["type"] = proxy_type

        url = f"{self._server}/api/proxies?{urlencode(params)}"
        return await self._get(url)

    # -- internal ------------------------------------------------------------

    async def _get(self, url: str) -> ZenProxyFetchResult:
        def _do() -> ZenProxyFetchResult:
            req = urllib_request.Request(url, method="GET")
            try:
                with urllib_request.urlopen(req, timeout=self._timeout) as resp:
                    data = json.loads(resp.read().decode())
            except HTTPError as exc:
                body = exc.read().decode("utf-8", "replace")[:300]
                logger.warning(
                    "zenproxy http error: status=%s body=%s", exc.code, body
                )
                return ZenProxyFetchResult(error=f"HTTP {exc.code}: {body}")
            except URLError as exc:
                logger.warning("zenproxy connection failed: reason=%s", exc.reason)
                return ZenProxyFetchResult(error=f"Connection failed: {exc.reason}")
            except Exception as exc:
                logger.warning("zenproxy request failed: error=%s", exc)
                return ZenProxyFetchResult(error=str(exc))

            raw_proxies = data.get("proxies", [])
            proxies: list[ZenProxyNode] = []
            for p in raw_proxies:
                quality = p.get("quality", {}) or {}
                proxies.append(
                    ZenProxyNode(
                        proxy_id=p.get("id", ""),
                        name=p.get("name", ""),
                        proxy_type=p.get("type", ""),
                        server=p.get("server", ""),
                        port=p.get("port", 0),
                        local_port=p.get("local_port", 0),
                        country=quality.get("country", ""),
                        chatgpt=quality.get("chatgpt", False),
                        google=quality.get("google", False),
                        is_residential=quality.get("is_residential", False),
                        risk_score=quality.get("risk_score", 0.0),
                        risk_level=quality.get("risk_level", "Unknown"),
                        outbound=p.get("outbound", {}),
                    )
                )
            return ZenProxyFetchResult(
                proxies=proxies,
                total=data.get("count", len(proxies)),
            )

        return await asyncio.to_thread(_do)


# ---------------------------------------------------------------------------
# ZenProxy pool sync helper
# ---------------------------------------------------------------------------


def _build_client_from_config() -> ZenProxyClient | None:
    """Build a ZenProxyClient from the current config snapshot, or None."""
    cfg = get_config()
    server = cfg.get_str("proxy.zenproxy.server", "")
    api_key = cfg.get_str("proxy.zenproxy.api_key", "")
    if not server or not api_key:
        return None
    timeout = cfg.get_int("proxy.zenproxy.timeout_sec", 30)
    return ZenProxyClient(server=server, api_key=api_key, timeout_sec=timeout)


async def fetch_zenproxy_pool() -> list[str]:
    """Fetch proxy URLs from ZenProxy and return a list usable by the pool.

    Returns proxy URLs that curl_cffi can use directly (http / socks5 / socks4).
    For protocol proxies (vmess, vless, etc.) a warning is logged — those
    require a local sing-box-zenproxy bridge.
    """
    client = _build_client_from_config()
    if client is None:
        return []

    cfg = get_config()
    count = cfg.get_int("proxy.zenproxy.pool_size", 50)
    country = cfg.get_str("proxy.zenproxy.country", "")
    proxy_type = cfg.get_str("proxy.zenproxy.proxy_type", "")
    chatgpt = cfg.get_bool("proxy.zenproxy.chatgpt", False)
    google = cfg.get_bool("proxy.zenproxy.google", False)
    residential = cfg.get_bool("proxy.zenproxy.residential", False)
    risk_max = cfg.get_float("proxy.zenproxy.risk_max", 0.0)
    prefer_client_api = cfg.get_bool("proxy.zenproxy.use_client_api", True)

    fetch_fn = client.client_fetch if prefer_client_api else client.fetch
    result = await fetch_fn(
        count=count,
        country=country,
        proxy_type=proxy_type or "",
        chatgpt=chatgpt,
        google=google,
        residential=residential,
        risk_max=risk_max,
    )

    if result.error:
        logger.error("zenproxy pool fetch failed: error=%s", result.error)
        return []

    direct: list[str] = []
    proto: list[str] = []
    for p in result.proxies:
        url = p.proxy_url
        if not url:
            continue
        if p.is_direct_usable:
            direct.append(url)
        else:
            proto.append(p.proxy_type)

    if proto:
        proto_types = ", ".join(sorted(set(proto)))
        logger.warning(
            "zenproxy returned %d protocol proxies (%s) that require a local "
            "sing-box-zenproxy bridge. Only HTTP/SOCKS proxies can be used "
            "directly. Consider setting proxy.zenproxy.proxy_type to 'http' "
            "or 'socks5' if your ZenProxy instance has them.",
            len(proto),
            proto_types,
        )

    logger.info(
        "zenproxy pool synced: fetched=%d direct_usable=%d protocol_skipped=%d",
        result.total,
        len(direct),
        len(proto),
    )
    return direct


# ---------------------------------------------------------------------------
# ZenProxy relay endpoint builder
# ---------------------------------------------------------------------------


def build_relay_url(target_url: str, *, method: str = "GET", **filters: Any) -> str | None:
    """Build a ZenProxy relay URL for the given target.

    Returns ``None`` when ZenProxy is not configured.
    """
    client = _build_client_from_config()
    if client is None:
        return None

    params: dict[str, Any] = {
        "api_key": client._api_key,
        "url": target_url,
        "method": method,
    }
    # Forward relevant filter params
    for key in ("country", "chatgpt", "google", "residential", "risk_max", "type"):
        if key in filters and filters[key]:
            params[key] = filters[key]

    return f"{client._server}/api/relay?{urlencode(params)}"


__all__ = [
    "ZenProxyClient",
    "ZenProxyNode",
    "ZenProxyFetchResult",
    "fetch_zenproxy_pool",
    "build_relay_url",
]
