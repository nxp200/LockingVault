/* argon2.js — adapter over the vendored Argon2 WASM build.
 *
 * The vendor library (hash-wasm) exposes window.hashwasm.argon2id with
 * its own parameter names. Everything else in this app expects the
 * argon2-browser shape — window.argon2.hash({ pass, salt, time, mem,
 * parallelism, hashLen, type }) resolving to { hash: Uint8Array }.
 *
 * Normalising here rather than in crypto.js means swapping the vendor
 * library later is a change to this file alone, and crypto.js never
 * learns which build is underneath it.
 *
 * Must load after the vendor script and before js/crypto.js, which
 * decides at load time whether Argon2 is available.
 */
window.LV = window.LV || {};

(function () {
  const lib = window.hashwasm;
  if (!lib || typeof lib.argon2id !== 'function') return; // crypto.js falls back to PBKDF2

  const ArgonType = { Argon2d: 0, Argon2i: 1, Argon2id: 2 };

  async function hash(opts) {
    const type = opts.type === undefined ? ArgonType.Argon2id : opts.type;
    if (type !== ArgonType.Argon2id) throw new Error('Only Argon2id is supported');

    // hash-wasm wants memorySize in KiB, same unit the VLT1 header
    // stores, so this passes straight through.
    const out = await lib.argon2id({
      password: opts.pass,
      salt: opts.salt,
      iterations: opts.time,
      memorySize: opts.mem,
      parallelism: opts.parallelism,
      hashLength: opts.hashLen,
      outputType: 'binary'
    });

    if (!(out instanceof Uint8Array) || out.length !== opts.hashLen) {
      throw new Error('Argon2 returned an unexpected result');
    }
    return { hash: out };
  }

  window.argon2 = { hash, ArgonType };
  LV.argon2Backend = 'hash-wasm';
})();
