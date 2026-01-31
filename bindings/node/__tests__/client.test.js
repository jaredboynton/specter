/**
 * Tests for Specter Node.js bindings.
 */

const {
  clientBuilder,
  FingerprintProfile,
  HttpVersion,
  CookieJar,
  RequestBuilder,
  timeoutsApiDefaults,
  timeoutsStreamingDefaults
} = require('../index');

describe('ClientBuilder', () => {
  test('builder creation', () => {
    const builder = clientBuilder();
    expect(builder).toBeDefined();
  });

  test('build client', () => {
    const client = clientBuilder().build();
    expect(client).toBeDefined();
  });

  test('fingerprint chrome', () => {
    const client = clientBuilder()
      .fingerprint(FingerprintProfile.Chrome142)
      .build();
    expect(client).toBeDefined();
  });

  test('fingerprint firefox', () => {
    const client = clientBuilder()
      .fingerprint(FingerprintProfile.Firefox133)
      .build();
    expect(client).toBeDefined();
  });

  test('fingerprint none', () => {
    const client = clientBuilder()
      .fingerprint(FingerprintProfile.None)
      .build();
    expect(client).toBeDefined();
  });

  test('prefer http2', () => {
    const client = clientBuilder()
      .preferHttp2(true)
      .build();
    expect(client).toBeDefined();
  });

  test('h3 upgrade', () => {
    const client = clientBuilder()
      .h3Upgrade(true)
      .build();
    expect(client).toBeDefined();
  });

  test('api timeouts', () => {
    const client = clientBuilder().apiTimeouts().build();
    expect(client).toBeDefined();
  });

  test('streaming timeouts', () => {
    const client = clientBuilder().streamingTimeouts().build();
    expect(client).toBeDefined();
  });

  test('custom timeouts', () => {
    const timeouts = timeoutsApiDefaults();
    const client = clientBuilder().timeouts(timeouts).build();
    expect(client).toBeDefined();
  });

  test('individual timeouts', () => {
    const client = clientBuilder()
      .totalTimeout(30.0)
      .connectTimeout(5.0)
      .ttfbTimeout(10.0)
      .readTimeout(60.0)
      .build();
    expect(client).toBeDefined();
  });

  test('localhost invalid certs', () => {
    const client = clientBuilder()
      .localhostAllowsInvalidCerts(true)
      .build();
    expect(client).toBeDefined();
  });

  test('platform roots', () => {
    const client = clientBuilder()
      .withPlatformRoots(true)
      .build();
    expect(client).toBeDefined();
  });
});

describe('RequestBuilder', () => {
  let client;

  beforeEach(() => {
    client = clientBuilder().build();
  });

  test('request builder creation', () => {
    const request = client.get('https://httpbin.org/get');
    expect(request).toBeDefined();
    expect(request).toBeInstanceOf(RequestBuilder);
  });

  test('all HTTP method request builders', () => {
    expect(client.get('https://example.com')).toBeInstanceOf(RequestBuilder);
    expect(client.post('https://example.com')).toBeInstanceOf(RequestBuilder);
    expect(client.put('https://example.com')).toBeInstanceOf(RequestBuilder);
    expect(client.delete('https://example.com')).toBeInstanceOf(RequestBuilder);
    expect(client.patch('https://example.com')).toBeInstanceOf(RequestBuilder);
    expect(client.head('https://example.com')).toBeInstanceOf(RequestBuilder);
    expect(client.options('https://example.com')).toBeInstanceOf(RequestBuilder);
  });

  test('arbitrary HTTP method request builder', () => {
    const request = client.request('PURGE', 'https://example.com/cache');
    expect(request).toBeInstanceOf(RequestBuilder);
  });

  test('header method returns this for chaining', () => {
    const request = client.get('https://httpbin.org/get');
    const result = request.header('X-Custom-Header', 'value');
    expect(result).toBe(request);
  });

  test('headers method returns this for chaining', () => {
    const request = client.get('https://httpbin.org/get');
    const result = request.headers([['Authorization', 'Bearer token']]);
    expect(result).toBe(request);
  });

  test('body method returns this for chaining', () => {
    const request = client.post('https://httpbin.org/post');
    const result = request.body(Buffer.from('test'));
    expect(result).toBe(request);
  });

  test('json method returns this for chaining', () => {
    const request = client.post('https://httpbin.org/post');
    const result = request.json('{"key": "value"}');
    expect(result).toBe(request);
  });

  test('form method returns this for chaining', () => {
    const request = client.post('https://httpbin.org/post');
    const result = request.form('key=value');
    expect(result).toBe(request);
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
    client = clientBuilder().build();
  });

  test('basic GET request', async () => {
    const response = await client.get('https://httpbin.org/get').send();
    expect(response.status).toBe(200);
    expect(response.isSuccess).toBe(true);
  }, 30000);

  test('GET with custom headers', async () => {
    const response = await client.get('https://httpbin.org/get')
      .header('X-Custom-Header', 'test-value')
      .send();
    expect(response.status).toBe(200);
    // httpbin returns the headers in the response body
    const body = JSON.parse(response.json());
    expect(body.headers['X-Custom-Header']).toBe('test-value');
  }, 30000);

  test('POST request', async () => {
    const response = await client.post('https://httpbin.org/post').send();
    expect(response.status).toBe(200);
  }, 30000);

  test('POST with JSON body', async () => {
    const response = await client.post('https://httpbin.org/post')
      .json(JSON.stringify({ name: 'test', value: 123 }))
      .send();
    expect(response.status).toBe(200);
    const body = JSON.parse(response.json());
    expect(body.json.name).toBe('test');
    expect(body.json.value).toBe(123);
  }, 30000);

  test('POST with form body', async () => {
    const response = await client.post('https://httpbin.org/post')
      .form('field1=value1&field2=value2')
      .send();
    expect(response.status).toBe(200);
    const body = JSON.parse(response.json());
    expect(body.form.field1).toBe('value1');
    expect(body.form.field2).toBe('value2');
  }, 30000);

  test('PUT request', async () => {
    const response = await client.put('https://httpbin.org/put').send();
    expect(response.status).toBe(200);
  }, 30000);

  test('DELETE request', async () => {
    const response = await client.delete('https://httpbin.org/delete').send();
    expect(response.status).toBe(200);
  }, 30000);

  test('PATCH request', async () => {
    const response = await client.patch('https://httpbin.org/patch')
      .json(JSON.stringify({ patch: 'data' }))
      .send();
    expect(response.status).toBe(200);
  }, 30000);

  test('HEAD request', async () => {
    const response = await client.head('https://httpbin.org/get').send();
    expect(response.status).toBe(200);
  }, 30000);

  test('OPTIONS request', async () => {
    const response = await client.options('https://httpbin.org/anything').send();
    expect(response.status).toBe(200);
  }, 30000);

  test('arbitrary method request', async () => {
    const response = await client.request('PURGE', 'https://httpbin.org/anything').send();
    expect(response.status).toBe(200);
  }, 30000);

  test('response properties', async () => {
    const response = await client.get('https://httpbin.org/get').send();
    expect(typeof response.status).toBe('number');
    expect(typeof response.isSuccess).toBe('boolean');
    expect(typeof response.isRedirect).toBe('boolean');
    expect(response.httpVersion).toBeDefined();
  }, 30000);

  test('get header', async () => {
    const response = await client.get('https://httpbin.org/get').send();
    const contentType = response.getHeader('content-type');
    expect(contentType).toBeDefined();
    expect(contentType).toContain('application/json');
  }, 30000);

  test('response bytes', async () => {
    const response = await client.get('https://httpbin.org/get').send();
    const data = response.bytes();
    expect(Buffer.isBuffer(data)).toBe(true);
    expect(data.length).toBeGreaterThan(0);
  }, 30000);

  test('response json', async () => {
    const response = await client.get('https://httpbin.org/get').send();
    const jsonStr = response.json();
    expect(typeof jsonStr).toBe('string');
    const data = JSON.parse(jsonStr);
    expect(typeof data).toBe('object');
    expect(data.url).toBeDefined();
  }, 30000);
});
