"""
Specter - Python bindings for the Specter HTTP client.

A high-performance async HTTP client with full TLS, HTTP/2, and HTTP/3
fingerprint control for browser impersonation.

Example:
    >>> import asyncio
    >>> import specter
    >>>
    >>> async def main():
    ...     builder = specter.Client.builder()
    ...     builder.fingerprint(specter.FingerprintProfile.Chrome142)
    ...     client = builder.build()
    ...     response = await client.get("https://httpbin.org/get")
    ...     print(response.status)
    ...     print(await response.text())
    ...
    >>> asyncio.run(main())
"""

from enum import Enum
from typing import Optional, Dict, List, Tuple, Any

class FingerprintProfile(Enum):
    """Browser fingerprint profiles for impersonation."""
    Chrome142 = ...
    Firefox133 = ...
    None = ...

class HttpVersion(Enum):
    """HTTP version preference."""
    Http1_1 = ...
    Http2 = ...
    Http3 = ...
    Http3Only = ...
    Auto = ...

class Timeouts:
    """Timeout configuration for HTTP requests.
    
    All timeouts are in seconds.
    
    - connect: TCP + TLS/QUIC handshake timeout
    - ttfb: Time-to-first-byte timeout
    - read_idle: Maximum time between received bytes (resets on each chunk)
    - write_idle: Maximum time between sent bytes
    - total: Absolute deadline for entire request
    - pool_acquire: Time to wait for a pooled connection
    """
    
    def __init__(self) -> None: ...
    
    @staticmethod
    def api_defaults() -> "Timeouts":
        """Sensible defaults for normal API calls."""
        ...
    
    @staticmethod
    def streaming_defaults() -> "Timeouts":
        """Sensible defaults for streaming responses."""
        ...
    
    def connect(self, timeout_secs: float) -> "Timeouts": ...
    def ttfb(self, timeout_secs: float) -> "Timeouts": ...
    def read_idle(self, timeout_secs: float) -> "Timeouts": ...
    def write_idle(self, timeout_secs: float) -> "Timeouts": ...
    def total(self, timeout_secs: float) -> "Timeouts": ...
    def pool_acquire(self, timeout_secs: float) -> "Timeouts": ...

class ClientBuilder:
    """Builder for creating HTTP clients.
    
    Note: Methods modify the builder in-place and return None.
    """
    
    def fingerprint(self, profile: FingerprintProfile) -> None:
        """Set the fingerprint profile."""
        ...
    
    def prefer_http2(self, prefer: bool) -> None:
        """Set HTTP/2 preference."""
        ...
    
    def h3_upgrade(self, enabled: bool) -> None:
        """Enable or disable automatic HTTP/3 upgrade via Alt-Svc headers."""
        ...
    
    def timeouts(self, timeouts: Timeouts) -> None:
        """Set timeout configuration."""
        ...
    
    def api_timeouts(self) -> None:
        """Use API-optimized timeout defaults."""
        ...
    
    def streaming_timeouts(self) -> None:
        """Use streaming-optimized timeout defaults."""
        ...
    
    def total_timeout(self, timeout_secs: float) -> None:
        """Set total request timeout in seconds."""
        ...
    
    def connect_timeout(self, timeout_secs: float) -> None:
        """Set connect timeout in seconds."""
        ...
    
    def ttfb_timeout(self, timeout_secs: float) -> None:
        """Set TTFB (time-to-first-byte) timeout in seconds."""
        ...
    
    def read_timeout(self, timeout_secs: float) -> None:
        """Set read idle timeout in seconds."""
        ...
    
    def danger_accept_invalid_certs(self, accept: bool) -> None:
        """Skip TLS certificate verification (DANGEROUS - for testing only)."""
        ...
    
    def localhost_allows_invalid_certs(self, allow: bool) -> None:
        """Automatically skip TLS certificate verification for localhost."""
        ...
    
    def with_platform_roots(self, enabled: bool) -> None:
        """Load root certificates from the OS certificate store."""
        ...
    
    def build(self) -> "Client":
        """Build the client."""
        ...

class Client:
    """HTTP client with TLS/HTTP2/HTTP3 fingerprint control."""
    
    @staticmethod
    def builder() -> ClientBuilder:
        """Create a new client builder."""
        ...
    
    async def get(self, url: str) -> "Response":
        """Make a GET request."""
        ...
    
    async def post(self, url: str) -> "Response":
        """Make a POST request."""
        ...
    
    async def put(self, url: str) -> "Response":
        """Make a PUT request."""
        ...
    
    async def delete(self, url: str) -> "Response":
        """Make a DELETE request."""
        ...

class Response:
    """HTTP response with decompression support."""
    
    @property
    def status(self) -> int:
        """HTTP status code."""
        ...
    
    @property
    def headers(self) -> Dict[str, str]:
        """Response headers as a dictionary."""
        ...
    
    def headers_list(self) -> List[Tuple[str, str]]:
        """Get all headers as a list of (name, value) tuples."""
        ...
    
    def get_header(self, name: str) -> Optional[str]:
        """Get a specific header value by name."""
        ...
    
    async def text(self) -> str:
        """Get the response body as text (with decompression if needed)."""
        ...
    
    async def bytes(self) -> bytes:
        """Get the response body as bytes."""
        ...
    
    async def json(self) -> Any:
        """Parse the response body as JSON."""
        ...
    
    @property
    def http_version(self) -> str:
        """HTTP version string."""
        ...
    
    @property
    def effective_url(self) -> Optional[str]:
        """Effective URL (after redirects)."""
        ...
    
    @property
    def is_success(self) -> bool:
        """Check if the response status is successful (2xx)."""
        ...
    
    @property
    def is_redirect(self) -> bool:
        """Check if the response is a redirect (3xx)."""
        ...
    
    @property
    def redirect_url(self) -> Optional[str]:
        """Get the redirect URL from Location header if present."""
        ...
    
    @property
    def content_type(self) -> Optional[str]:
        """Get the Content-Type header value."""
        ...

class CookieJar:
    """Cookie jar for manual cookie management."""
    
    def __init__(self) -> None: ...
    
    def __len__(self) -> int: ...
    
    @property
    def is_empty(self) -> bool: ...
