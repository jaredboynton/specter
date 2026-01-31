/**
 * Specter - Node.js bindings for the Specter HTTP client.
 *
 * A high-performance async HTTP client with full TLS, HTTP/2, and HTTP/3
 * fingerprint control for browser impersonation.
 *
 * @example
 * const { clientBuilder, FingerprintProfile } = require('@specter/client');
 *
 * async function main() {
 *   // Create a client with default settings
 *   const client = clientBuilder().build();
 *
 *   // Simple GET request
 *   const response = await client.get('https://httpbin.org/get').send();
 *   console.log(`Status: ${response.status}`);
 *   console.log(response.text());
 *
 *   // POST with JSON body
 *   const response2 = await client.post('https://api.example.com/data')
 *     .header('Authorization', 'Bearer token')
 *     .json(JSON.stringify({ name: 'test' }))
 *     .send();
 *   console.log(JSON.parse(response2.json()));
 * }
 *
 * main();
 */

const { loadBinding } = require('@napi-rs/wasm-runtime');
const path = require('path');

// Try to load the native binding
let nativeBinding;

// Platform to binary name mapping based on napi-rs naming convention
// Format: specter.{os}-{arch}[-{libc}].node
const platformBinaries = {
  'darwin-arm64': 'specter.darwin-arm64.node',
  'darwin-x64': 'specter.darwin-x64.node',
  'linux-arm64-gnu': 'specter.linux-arm64-gnu.node',
  'linux-x64-gnu': 'specter.linux-x64-gnu.node',
  'linux-x64-musl': 'specter.linux-x64-musl.node',
  'win32-x64-msvc': 'specter.win32-x64-msvc.node',
};

function getPlatformKey() {
  const platform = process.platform;
  const arch = process.arch;

  if (platform === 'darwin') {
    return `darwin-${arch}`;
  }
  if (platform === 'win32') {
    return `win32-${arch}-msvc`;
  }
  if (platform === 'linux') {
    // Check if we're on musl by looking at the libc
    const isMusl = (() => {
      try {
        const { execSync } = require('child_process');
        return execSync('ldd --version 2>&1').toString().includes('musl');
      } catch {
        return false;
      }
    })();
    return `linux-${arch}-${isMusl ? 'musl' : 'gnu'}`;
  }
  return null;
}

function loadNativeBinding() {
  // Try platform-specific binary first
  const platformKey = getPlatformKey();
  if (platformKey && platformBinaries[platformKey]) {
    try {
      nativeBinding = require(`./${platformBinaries[platformKey]}`);
      return nativeBinding;
    } catch (e) {
      // Continue to fallback
    }
  }

  // Try all known binaries
  for (const binaryName of Object.values(platformBinaries)) {
    try {
      nativeBinding = require(`./${binaryName}`);
      return nativeBinding;
    } catch (e) {
      // Continue to next platform
    }
  }

  // Try loading from build directory
  try {
    nativeBinding = require('./specter.node');
    return nativeBinding;
  } catch (e) {
    // Fall through
  }

  // Try loading from target
  try {
    nativeBinding = require('./build/Release/specter.node');
    return nativeBinding;
  } catch (e) {
    // Fall through
  }

  throw new Error(
    `Failed to load native binding for Specter. ` +
    `Please ensure you've built the native module with "npm run build".`
  );
}

// Load the binding
const binding = loadNativeBinding();

// Export the native types
module.exports.Client = binding.Client;
module.exports.ClientBuilder = binding.ClientBuilder;
module.exports.RequestBuilder = binding.RequestBuilder;
module.exports.Response = binding.Response;
module.exports.CookieJar = binding.CookieJar;
module.exports.FingerprintProfile = binding.FingerprintProfile;
module.exports.HttpVersion = binding.HttpVersion;
module.exports.Timeouts = binding.Timeouts;
module.exports.clientBuilder = binding.clientBuilder;
module.exports.timeoutsApiDefaults = binding.timeoutsApiDefaults;
module.exports.timeoutsStreamingDefaults = binding.timeoutsStreamingDefaults;
