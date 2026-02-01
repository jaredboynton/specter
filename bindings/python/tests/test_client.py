"""Tests for Specter Python bindings."""

import pytest
import specter


class TestClientBuilder:
    """Test ClientBuilder configuration."""

    def test_builder_creation(self):
        """Test creating a client builder."""
        builder = specter.Client.builder()
        assert builder is not None

    def test_build_client(self):
        """Test building a client."""
        builder = specter.Client.builder()
        client = builder.build()
        assert client is not None
        assert isinstance(client, specter.Client)

    def test_fingerprint_chrome(self):
        """Test setting Chrome fingerprint."""
        builder = specter.Client.builder()
        builder.fingerprint(specter.FingerprintProfile.Chrome142)
        client = builder.build()
        assert client is not None

    def test_fingerprint_firefox(self):
        """Test setting Firefox fingerprint."""
        builder = specter.Client.builder()
        builder.fingerprint(specter.FingerprintProfile.Firefox133)
        client = builder.build()
        assert client is not None

    def test_fingerprint_none(self):
        """Test setting no fingerprint."""
        builder = specter.Client.builder()
        builder.fingerprint(specter.FingerprintProfile.NoFingerprint)
        client = builder.build()
        assert client is not None

    def test_prefer_http2(self):
        """Test HTTP/2 preference setting."""
        builder = specter.Client.builder()
        builder.prefer_http2(True)
        client = builder.build()
        assert client is not None

    def test_h3_upgrade(self):
        """Test HTTP/3 upgrade setting."""
        builder = specter.Client.builder()
        builder.h3_upgrade(True)
        client = builder.build()
        assert client is not None

    def test_api_timeouts(self):
        """Test API timeout preset."""
        builder = specter.Client.builder()
        builder.api_timeouts()
        client = builder.build()
        assert client is not None

    def test_streaming_timeouts(self):
        """Test streaming timeout preset."""
        builder = specter.Client.builder()
        builder.streaming_timeouts()
        client = builder.build()
        assert client is not None

    def test_custom_timeouts(self):
        """Test custom timeout configuration."""
        timeouts = (specter.Timeouts()
            .connect(5.0)
            .ttfb(10.0)
            .total(30.0))
        builder = specter.Client.builder()
        builder.timeouts(timeouts)
        client = builder.build()
        assert client is not None

    def test_individual_timeouts(self):
        """Test individual timeout setters."""
        builder = specter.Client.builder()
        builder.total_timeout(30.0)
        builder.connect_timeout(5.0)
        builder.ttfb_timeout(10.0)
        builder.read_timeout(60.0)
        client = builder.build()
        assert client is not None

    def test_localhost_invalid_certs(self):
        """Test localhost invalid certs setting."""
        builder = specter.Client.builder()
        builder.localhost_allows_invalid_certs(True)
        client = builder.build()
        assert client is not None

    def test_platform_roots(self):
        """Test platform roots setting."""
        builder = specter.Client.builder()
        builder.with_platform_roots(True)
        client = builder.build()
        assert client is not None


class TestRequestBuilder:
    """Test RequestBuilder for headers and body."""

    def test_request_builder_creation(self):
        """Test creating a request builder."""
        client = specter.Client.builder().build()
        request = client.get("https://httpbin.org/get")
        assert isinstance(request, specter.RequestBuilder)

    def test_request_builder_methods(self):
        """Test all HTTP method request builders."""
        client = specter.Client.builder().build()
        
        get_req = client.get("https://example.com")
        assert isinstance(get_req, specter.RequestBuilder)
        
        post_req = client.post("https://example.com")
        assert isinstance(post_req, specter.RequestBuilder)
        
        put_req = client.put("https://example.com")
        assert isinstance(put_req, specter.RequestBuilder)
        
        delete_req = client.delete("https://example.com")
        assert isinstance(delete_req, specter.RequestBuilder)
        
        patch_req = client.patch("https://example.com")
        assert isinstance(patch_req, specter.RequestBuilder)
        
        head_req = client.head("https://example.com")
        assert isinstance(head_req, specter.RequestBuilder)
        
        options_req = client.options("https://example.com")
        assert isinstance(options_req, specter.RequestBuilder)

    def test_request_arbitrary_method(self):
        """Test arbitrary HTTP method request builder."""
        client = specter.Client.builder().build()
        request = client.request("PURGE", "https://example.com/cache")
        assert isinstance(request, specter.RequestBuilder)

    def test_request_header(self):
        """Test adding a single header."""
        client = specter.Client.builder().build()
        request = client.get("https://httpbin.org/get")
        request.header("X-Custom-Header", "test-value")
        # Should not raise

    def test_request_headers(self):
        """Test setting multiple headers."""
        client = specter.Client.builder().build()
        request = client.get("https://httpbin.org/get")
        request.headers([("Authorization", "Bearer token"), ("X-Request-ID", "123")])
        # Should not raise

    def test_request_body(self):
        """Test setting request body."""
        client = specter.Client.builder().build()
        request = client.post("https://httpbin.org/post")
        request.body(b"test body data")
        # Should not raise

    def test_request_json(self):
        """Test setting JSON body."""
        client = specter.Client.builder().build()
        request = client.post("https://httpbin.org/post")
        request.json('{"key": "value"}')
        # Should not raise

    def test_request_form(self):
        """Test setting form body."""
        client = specter.Client.builder().build()
        request = client.post("https://httpbin.org/post")
        request.form("key=value&foo=bar")
        # Should not raise


class TestTimeouts:
    """Test Timeouts configuration."""

    def test_timeouts_new(self):
        """Test creating empty timeouts."""
        timeouts = specter.Timeouts()
        assert timeouts is not None

    def test_timeouts_api_defaults(self):
        """Test API defaults preset."""
        timeouts = specter.Timeouts.api_defaults()
        assert timeouts is not None

    def test_timeouts_streaming_defaults(self):
        """Test streaming defaults preset."""
        timeouts = specter.Timeouts.streaming_defaults()
        assert timeouts is not None

    def test_timeouts_builder_pattern(self):
        """Test timeouts builder pattern."""
        timeouts = (specter.Timeouts()
            .connect(10.0)
            .ttfb(30.0)
            .read_idle(60.0)
            .write_idle(30.0)
            .total(120.0)
            .pool_acquire(5.0))
        assert timeouts is not None


class TestFingerprintProfile:
    """Test FingerprintProfile enum."""

    def test_chrome142_exists(self):
        """Test Chrome142 profile exists."""
        assert specter.FingerprintProfile.Chrome142 is not None

    def test_firefox133_exists(self):
        """Test Firefox133 profile exists."""
        assert specter.FingerprintProfile.Firefox133 is not None

    def test_nofingerprint_exists(self):
        """Test NoFingerprint profile exists."""
        assert specter.FingerprintProfile.NoFingerprint is not None


class TestHttpVersion:
    """Test HttpVersion enum."""

    def test_http1_1_exists(self):
        """Test Http1_1 version exists."""
        assert specter.HttpVersion.Http1_1 is not None

    def test_http2_exists(self):
        """Test Http2 version exists."""
        assert specter.HttpVersion.Http2 is not None

    def test_http3_exists(self):
        """Test Http3 version exists."""
        assert specter.HttpVersion.Http3 is not None

    def test_http3_only_exists(self):
        """Test Http3Only version exists."""
        assert specter.HttpVersion.Http3Only is not None

    def test_auto_exists(self):
        """Test Auto version exists."""
        assert specter.HttpVersion.Auto is not None


class TestCookieJar:
    """Test CookieJar."""

    def test_cookie_jar_new(self):
        """Test creating a new cookie jar."""
        jar = specter.CookieJar()
        assert jar is not None
        assert len(jar) == 0
        assert jar.is_empty


@pytest.mark.asyncio
class TestAsyncRequests:
    """Test async HTTP requests (requires network)."""

    async def test_get_request(self):
        """Test basic GET request."""
        builder = specter.Client.builder()
        client = builder.build()
        response = await client.get("https://httpbin.org/get").send()
        assert response.status == 200
        assert response.is_success

    async def test_get_with_headers(self):
        """Test GET request with custom headers."""
        builder = specter.Client.builder()
        client = builder.build()
        request = client.get("https://httpbin.org/get")
        request.header("X-Custom-Header", "test-value")
        response = await request.send()
        assert response.status == 200
        # httpbin returns the headers in the response body
        body = await response.json()
        assert body["headers"]["X-Custom-Header"] == "test-value"

    async def test_post_request(self):
        """Test basic POST request."""
        builder = specter.Client.builder()
        client = builder.build()
        response = await client.post("https://httpbin.org/post").send()
        assert response.status == 200

    async def test_post_with_json(self):
        """Test POST request with JSON body."""
        builder = specter.Client.builder()
        client = builder.build()
        request = client.post("https://httpbin.org/post")
        request.json('{"name": "test", "value": 123}')
        response = await request.send()
        assert response.status == 200
        body = await response.json()
        assert body["json"]["name"] == "test"
        assert body["json"]["value"] == 123

    async def test_post_with_form(self):
        """Test POST request with form body."""
        builder = specter.Client.builder()
        client = builder.build()
        request = client.post("https://httpbin.org/post")
        request.form("field1=value1&field2=value2")
        response = await request.send()
        assert response.status == 200
        body = await response.json()
        assert body["form"]["field1"] == "value1"
        assert body["form"]["field2"] == "value2"

    async def test_put_request(self):
        """Test basic PUT request."""
        builder = specter.Client.builder()
        client = builder.build()
        response = await client.put("https://httpbin.org/put").send()
        assert response.status == 200

    async def test_delete_request(self):
        """Test basic DELETE request."""
        builder = specter.Client.builder()
        client = builder.build()
        response = await client.delete("https://httpbin.org/delete").send()
        assert response.status == 200

    async def test_patch_request(self):
        """Test PATCH request."""
        builder = specter.Client.builder()
        client = builder.build()
        request = client.patch("https://httpbin.org/patch")
        request.json('{"patch": "data"}')
        response = await request.send()
        assert response.status == 200

    async def test_head_request(self):
        """Test HEAD request."""
        builder = specter.Client.builder()
        client = builder.build()
        response = await client.head("https://httpbin.org/get").send()
        assert response.status == 200

    async def test_options_request(self):
        """Test OPTIONS request."""
        builder = specter.Client.builder()
        client = builder.build()
        response = await client.options("https://httpbin.org/anything").send()
        assert response.status == 200

    async def test_arbitrary_method_request(self):
        """Test arbitrary method request."""
        builder = specter.Client.builder()
        client = builder.build()
        response = await client.request("PURGE", "https://httpbin.org/anything").send()
        assert response.status == 200

    async def test_response_properties(self):
        """Test response properties."""
        builder = specter.Client.builder()
        client = builder.build()
        response = await client.get("https://httpbin.org/get").send()
        
        assert isinstance(response.status, int)
        assert isinstance(response.is_success, bool)
        assert isinstance(response.is_redirect, bool)
        assert response.http_version is not None

    async def test_get_header(self):
        """Test getting specific header."""
        builder = specter.Client.builder()
        client = builder.build()
        response = await client.get("https://httpbin.org/get").send()
        content_type = response.get_header("content-type")
        assert content_type is not None
        assert "application/json" in content_type

    async def test_response_bytes(self):
        """Test getting response as bytes."""
        builder = specter.Client.builder()
        client = builder.build()
        response = await client.get("https://httpbin.org/get").send()
        data = await response.bytes()
        assert isinstance(data, bytes)
        assert len(data) > 0

    async def test_response_json(self):
        """Test parsing response as JSON."""
        builder = specter.Client.builder()
        client = builder.build()
        response = await client.get("https://httpbin.org/get").send()
        data = await response.json()
        assert isinstance(data, dict)
        assert "url" in data
