/**
 * Specter - Node.js bindings for the Specter HTTP client.
 *
 * A high-performance async HTTP client with full TLS, HTTP/2, and HTTP/3
 * fingerprint control for browser impersonation.
 *
 * @example
 * const { Client, FingerprintProfile } = require('@specter/client');
 *
 * async function main() {
 *   // Create a client with default settings
 *   const client = Client.builder().build();
 *
 *   // Make a GET request
 *   const response = await client.get('https://httpbin.org/get');
 *   console.log(`Status: ${response.status}`);
 *   console.log(await response.text());
 * }
 *
 * main();
 */

const { loadBinding } = require('@napi-rs/wasm-runtime');
const path = require('path');

// Try to load the native binding
let nativeBinding;

const platforms = [
  ['darwin', 'arm64'],
  ['darwin', 'x64'],
  ['linux', 'arm64'],
  ['linux', 'x64'],
  ['win32', 'arm64'],
  ['win32', 'x64'],
];

function loadNativeBinding() {
  // First try to load from prebuilt
  for (const [platform, arch] of platforms) {
    try {
      const binaryName = `specter.${platform}-${arch}.node`;
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
module.exports.Response = binding.Response;
module.exports.CookieJar = binding.CookieJar;
module.exports.FingerprintProfile = binding.FingerprintProfile;
module.exports.HttpVersion = binding.HttpVersion;
module.exports.Timeouts = binding.Timeouts;
module.exports.timeoutsApiDefaults = binding.timeoutsApiDefaults;
module.exports.timeoutsStreamingDefaults = binding.timeoutsStreamingDefaults;
