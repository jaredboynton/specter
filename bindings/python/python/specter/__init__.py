"""
Specter - Python bindings for the Specter HTTP client.

A high-performance async HTTP client with full TLS, HTTP/2, and HTTP/3
fingerprint control for browser impersonation.

Basic usage:
    >>> import asyncio
    >>> import specter
    >>>
    >>> async def main():
    ...     client = specter.Client.builder().build()
    ...     response = await client.get("https://httpbin.org/get")
    ...     print(f"Status: {response.status}")
    ...     print(await response.text())
    ...
    >>> asyncio.run(main())

With fingerprinting:
    >>> client = (specter.Client.builder()
    ...     .fingerprint(specter.FingerprintProfile.Chrome142)
    ...     .build())

With custom timeouts:
    >>> timeouts = (specter.Timeouts()
    ...     .connect(5.0)
    ...     .total(30.0))
    >>> client = specter.Client.builder().timeouts(timeouts).build()
"""

from .specter import (
    Client,
    ClientBuilder,
    Response,
    CookieJar,
    FingerprintProfile,
    HttpVersion,
    Timeouts,
)

__version__ = "1.1.0"
__all__ = [
    "Client",
    "ClientBuilder", 
    "Response",
    "CookieJar",
    "FingerprintProfile",
    "HttpVersion",
    "Timeouts",
]
