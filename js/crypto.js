/* crypto.js — key derivation and authenticated encryption.
 *
 * Argon2id is preferred but is not available in WebCrypto. If an
 * Argon2 WASM build has been loaded as window.argon2 it is used;
 * otherwise this falls back to PBKDF2-SHA256, which is recorded in
 * the header so both kinds of vault stay readable either way.
 */
window.LV = window.LV || {};

LV.crypto = (function () {
  const F = LV.format;

  const HAS_ARGON2 = typeof window.argon2 !== 'undefined';

  const DEFAULT_PARAMS = HAS_ARGON2
    ? { kdf: F.KDF_ARGON2ID, memoryKiB: 65536, iterations: 3, parallelism: 1 }
    : { kdf: F.KDF_PBKDF2, memoryKiB: 0, iterations: 600000, parallelism: 1 };

  // Canonical form fed to the KDF. Must match byte for byte on every
  // unlock, so collapse whitespace and case. Note the EFF wordlist
  // contains hyphenated words (t-shirt, yo-yo), so a hyphen can never
  // be treated as a word separator.
  function canonical(input) {
    return String(input).normalize('NFKC').toLowerCase().replace(/\s+/g, ' ').trim();
  }

  async function deriveKey(phrase, salt, params) {
    const pass = canonical(phrase);
    let raw;

    if (params.kdf === F.KDF_ARGON2ID) {
      if (!HAS_ARGON2) throw new Error('This vault needs Argon2, which this build does not include');
      const r = await window.argon2.hash({
        pass,
        salt,
        time: params.iterations,
        mem: params.memoryKiB,
        parallelism: params.parallelism,
        hashLen: 32,
        type: window.argon2.ArgonType.Argon2id
      });
      raw = r.hash;
    } else {
      const base = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveBits']);
      raw = new Uint8Array(await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt, iterations: params.iterations, hash: 'SHA-256' }, base, 256));
    }

    return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }

  async function encryptVault(data, phrase, params) {
    params = params || DEFAULT_PARAMS;
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const nonce = crypto.getRandomValues(new Uint8Array(12)); // never reused
    const header = F.buildHeader(params, salt, nonce);
    const key = await deriveKey(phrase, salt, params);

    const pt = F.padBytes(JSON.stringify(data));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: header, tagLength: 128 }, key, pt));

    const out = new Uint8Array(F.HEADER_LEN + ct.length);
    out.set(header, 0);
    out.set(ct, F.HEADER_LEN);
    return out;
  }

  async function decryptVault(bytes, phrase) {
    const { header, params, salt, nonce } = F.parseHeader(bytes);
    const key = await deriveKey(phrase, salt, params);

    let pt;
    try {
      pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: header, tagLength: 128 },
        key, bytes.subarray(F.HEADER_LEN));
    } catch (e) {
      // Wrong passphrase and tampered file are deliberately
      // indistinguishable. GCM verifies the tag before releasing
      // any plaintext, so a failed unlock leaks nothing.
      throw new Error('Could not unlock. Check the passphrase.');
    }

    return { data: JSON.parse(new TextDecoder().decode(pt).trimEnd()), params };
  }

  return { HAS_ARGON2, DEFAULT_PARAMS, canonical, deriveKey, encryptVault, decryptVault };
})();
