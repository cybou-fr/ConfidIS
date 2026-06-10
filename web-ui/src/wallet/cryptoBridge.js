// Thin singleton wrapper around the `confidis-crypto-wasm` package.
//
// Loading WebAssembly is async (`init()` returns a Promise) but we only want to
// pay that cost once per page load. Every wallet path calls `loadCrypto()` which
// caches the result. The returned object exposes the same camelCase API as the
// underlying `.wasm` plus `init`.
//
// All comments in plain English so contributors (including non-Russian
// speakers) can follow the threat-model rationale.
//
// ## Threat-model contract
//
// The Slice-1 wallet runs the entire crypto on the **main thread**. This is a
// known interim choice — the production target is a dedicated Web Worker
// (`ROADMAP.md` § Public Testnet Launch Gate). A different packaging model only requires moving the
// `loadCrypto` call inside a Worker and replacing direct function calls with
// `postMessage` round-trips; the function signatures stay identical.
//
// Until the Worker move lands, callers MUST:
//
// - keep signing-key hex strings in short-lived JS variables only,
// - never write the signing key into React state, props, context, or any
//   storage that survives the current event-loop task,
// - never log a signing key,
// - never include a signing key in an exception message.

import init, * as wasm from "confidis-crypto-wasm";

let _loadPromise = null;

/**
 * Idempotent loader. First call instantiates the `.wasm` module and resolves
 * with the loaded namespace object. Subsequent calls return the same cached
 * promise so every component can `await loadCrypto()` without coordination.
 *
 * Returns the module namespace so callers can do
 * `const { generateMnemonic24 } = await loadCrypto();`.
 */
export function loadCrypto() {
  if (_loadPromise === null) {
    _loadPromise = init().then(() => wasm);
  }
  return _loadPromise;
}

/**
 * Convenience helper for components that only need to know whether the WASM
 * module is ready, without depending on its return value.
 */
export async function ensureCryptoLoaded() {
  await loadCrypto();
}

// Re-export the wasm namespace for callers that want the canonical names.
// The `loadCrypto()` step still has to happen first — see comments above.
export { wasm };
