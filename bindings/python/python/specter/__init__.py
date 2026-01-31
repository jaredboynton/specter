"""
Specter - Python bindings for the Specter HTTP client.

A high-performance async HTTP client with full TLS, HTTP/2, and HTTP/3
fingerprint control for browser impersonation.

Basic usage:
    >>> import asyncio
    >>> import specter
    >>>
    >>> async def main():
    ...     # Create a client with default settings
    ...     client = specter.Client.builder().build()
    ...     
    ...     # Simple GET request
    ...     response = await client.get("https://httpbin.org/get").send()
    ...     print(f"Status: {response.status}")
    ...     print(await response.text())
    ...
    >>> asyncio.run(main())

With headers and body:
    >>> async def main():
    ...     client = specter.Client.builder().build()
    ...     
    ...     # POST with JSON body
    ...     request = client.post("https://api.example.com/data")
    ...     request.header("Authorization", "Bearer token")
    ...     request.json('{"name": "test"}')
    ...     response = await request.send()
    ...     
    ...     # Or chain the calls
    ...     response = await (client.post("https://api.example.com/data")
    ...         .header("Authorization", "Bearer token")
    ...         .json('{"name": "test"}')
    ...         .send())
    ...
    >>> asyncio.run(main())

With fingerprinting:
    >>> builder = specter.Client.builder()
    >>> builder.fingerprint(specter.FingerprintProfile.Chrome142)
    >>> client = builder.build()

With custom timeouts:
    >>> timeouts = (specter.Timeouts()
    ...     .connect(5.0)
    ...     .total(30.0))
    >>> builder = specter.Client.builder()
    >>> builder.timeouts(timeouts)
    >>> client = builder.build()
"""

from .specter import (
    Client,
    ClientBuilder,
    RequestBuilder,
    Response,
    CookieJar,
    FingerprintProfile,
    HttpVersion,
    Timeouts,
)

__version__ = "1.2.0"
__all__ = [
    "Client",
    "ClientBuilder",
    "RequestBuilder",
    "Response",
    "CookieJar",
    "FingerprintProfile",
    "HttpVersion",
    "Timeouts",
]
