/**
 * Tests for Specter Node.js bindings.
 */

const { 
  Client, 
  FingerprintProfile, 
  HttpVersion,
  CookieJar,
  timeoutsApiDefaults,
  timeoutsStreamingDefaults
} = require('../index');

describe('ClientBuilder', () => {
  test('builder creation', () => {
    const builder = Client.builder();
    expect(builder).toBeDefined();
  });

  test('build client', () => {
    const client = Client.builder().build();
    expect(client).toBeDefined();
  });

  test('fingerprint chrome', () => {
    const client = Client.builder()
      .fingerprint(FingerprintProfile.Chrome142)
      .build();
    expect(client).toBeDefined();
  });

  test('fingerprint firefox', () => {
    const client = Client.builder()
      .fingerprint(FingerprintProfile.Firefox133)
      .build();
    expect(client).toBeDefined();
  });

  test('fingerprint none', () => {
    const client = Client.builder()
      .fingerprint(FingerprintProfile.None)
      .build();
    expect(client).toBeDefined();
  });

  test('prefer http2', () => {
    const client = Client.builder()
      .preferHttp2(true)
      .build();
    expect(client).toBeDefined();
  });

  test('h3 upgrade', () => {
    const client = Client.builder()
      .h3Upgrade(true)
      .build();
    expect(client).toBeDefined();
  });

  test('api timeouts', () => {
    const client = Client.builder().apiTimeouts().build();
    expect(client).toBeDefined();
  });

  test('streaming timeouts', () => {
    const client = Client.builder().streamingTimeouts().build();
    expect(client).toBeDefined();
  });

  test('custom timeouts', () => {
    const timeouts = timeoutsApiDefaults();
    const client = Client.builder().timeouts(timeouts).build();
    expect(client).toBeDefined();
  });

  test('individual timeouts', () => {
    const client = Client.builder()
      .totalTimeout(30.0)
      .connectTimeout(5.0)
      .ttfbTimeout(10.0)
      .readTimeout(60.0)
      .build();
    expect(client).toBeDefined();
  });

  test('localhost invalid certs', () => {
    const client = Client.builder()
      .localhostAllowsInvalidCerts(true)
      .build();
    expect(client).toBeDefined();
  });

  test('platform roots', () => {
    const client = Client.builder()
      .withPlatformRoots(true)
      .build();
    expect(client).toBeDefined();
  });
});

describe('Timeouts', () => {
  test('api defaults', () => {
    const timeouts = timeoutsApiDefaults();
    expect(timeouts).toBeDefined();
    expect(timeouts.connect).toBe(10.0);
    expect(timeouts.ttfb).toBe(30.0);
    expect(timeouts.total).toBe(120.0);
  });

  test('streaming defaults', () => {
    const timeouts = timeoutsStreamingDefaults();
    expect(timeouts).toBeDefined();
    expect(timeouts.connect).toBe(10.0);
    expect(timeouts.total).toBeUndefined();
  });
});

describe('FingerprintProfile', () => {
  test('chrome142 exists', () => {
    expect(FingerprintProfile.Chrome142).toBeDefined();
  });

  test('firefox133 exists', () => {
    expect(FingerprintProfile.Firefox133).toBeDefined();
  });

  test('none exists', () => {
    expect(FingerprintProfile.None).toBeDefined();
  });
});

describe('HttpVersion', () => {
  test('http1_1 exists', () => {
    expect(HttpVersion.Http1_1).toBeDefined();
  });

  test('http2 exists', () => {
    expect(HttpVersion.Http2).toBeDefined();
  });

  test('http3 exists', () => {
    expect(HttpVersion.Http3).toBeDefined();
  });

  test('http3Only exists', () => {
    expect(HttpVersion.Http3Only).toBeDefined();
  });

  test('auto exists', () => {
    expect(HttpVersion.Auto).toBeDefined();
  });
});

describe('CookieJar', () => {
  test('create new', () => {
    const jar = new CookieJar();
    expect(jar).toBeDefined();
    expect(jar.length).toBe(0);
    expect(jar.isEmpty).toBe(true);
  });
});

describe('Async Requests', () => {
  let client;

  beforeEach(() => {
    client = Client.builder().build();
  });

  test('basic GET request', async () => {
    const response = await client.get('https://httpbin.org/get');
    expect(response.status).toBe(200);
    expect(response.isSuccess).toBe(true);
  }, 30000);

  test('GET response text', async () => {
    const response = await client.get('https://httpbin.org/get');
    const text = response.text();
    expect(typeof text).toBe('string');
    expect(text.length).toBeGreaterThan(0);
  }, 30000);

  test('GET response json', async () => {
    const response = await client.get('https://httpbin.org/get');
    const data = response.json();
    expect(typeof data).toBe('object');
    expect(data.url).toBeDefined();
  }, 30000);

  test('GET response headers', async () => {
    const response = await client.get('https://httpbin.org/get');
    const headers = response.headers;
    expect(typeof headers).toBe('object');
    expect(headers['content-type']).toBeDefined();
  }, 30000);

  test('POST request', async () => {
    const response = await client.post('https://httpbin.org/post');
    expect(response.status).toBe(200);
  }, 30000);

  test('PUT request', async () => {
    const response = await client.put('https://httpbin.org/put');
    expect(response.status).toBe(200);
  }, 30000);

  test('DELETE request', async () => {
    const response = await client.delete('https://httpbin.org/delete');
    expect(response.status).toBe(200);
  }, 30000);

  test('response properties', async () => {
    const response = await client.get('https://httpbin.org/get');
    expect(typeof response.status).toBe('number');
    expect(typeof response.isSuccess).toBe('boolean');
    expect(typeof response.isRedirect).toBe('boolean');
    expect(response.httpVersion).toBeDefined();
  }, 30000);

  test('get header', async () => {
    const response = await client.get('https://httpbin.org/get');
    const contentType = response.getHeader('content-type');
    expect(contentType).toBeDefined();
    expect(contentType).toContain('application/json');
  }, 30000);

  test('response bytes', async () => {
    const response = await client.get('https://httpbin.org/get');
    const data = response.bytes();
    expect(Buffer.isBuffer(data)).toBe(true);
    expect(data.length).toBeGreaterThan(0);
  }, 30000);
});
