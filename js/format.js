/* format.js — VLT1 container layout.
 *
 *  offset  size  field
 *  0       4     magic "VLT1"
 *  4       1     format version
 *  5       1     KDF id (1 = Argon2id, 2 = PBKDF2-SHA256)
 *  6       4     memory cost, KiB   (uint32 BE, 0 for PBKDF2)
 *  10      4     iterations         (uint32 BE)
 *  14      1     parallelism
 *  15      1     cipher id (1 = AES-256-GCM)
 *  16      16    salt
 *  32      12    nonce
 *  44      16    reserved (zero)
 *  60      1     header length
 *  61      ..    ciphertext + 16-byte GCM tag
 *
 * The whole header is passed as AEAD additional data, so KDF
 * parameters cannot be altered without failing authentication.
 */
window.LV = window.LV || {};

LV.format = (function () {
  const MAGIC = new Uint8Array([0x56, 0x4c, 0x54, 0x31]); // "VLT1"
  const HEADER_LEN = 61;
  const PAD_BLOCK = 4096;
  const VERSION = 0x01;
  const KDF_ARGON2ID = 0x01;
  const KDF_PBKDF2 = 0x02;
  const CIPHER_AES_GCM = 0x01;

  function buildHeader(params, salt, nonce) {
    const h = new Uint8Array(HEADER_LEN);
    const dv = new DataView(h.buffer);
    h.set(MAGIC, 0);
    h[4] = VERSION;
    h[5] = params.kdf;
    dv.setUint32(6, params.memoryKiB);
    dv.setUint32(10, params.iterations);
    h[14] = params.parallelism;
    h[15] = CIPHER_AES_GCM;
    h.set(salt, 16);
    h.set(nonce, 32);
    h[60] = HEADER_LEN;
    return h;
  }

  function parseHeader(bytes) {
    if (bytes.length < HEADER_LEN + 16) throw new Error('This file is too short to be a vault');
    const h = bytes.subarray(0, HEADER_LEN);
    if (!MAGIC.every((b, i) => h[i] === b)) throw new Error('This is not a vault file');
    if (h[4] !== VERSION) throw new Error('This vault was written by a newer version');
    if (h[5] !== KDF_ARGON2ID && h[5] !== KDF_PBKDF2) throw new Error('Unsupported key derivation');
    if (h[15] !== CIPHER_AES_GCM) throw new Error('Unsupported cipher');
    const dv = new DataView(h.buffer, h.byteOffset, HEADER_LEN);
    return {
      header: h,
      params: {
        kdf: h[5],
        memoryKiB: dv.getUint32(6),
        iterations: dv.getUint32(10),
        parallelism: h[14]
      },
      salt: h.subarray(16, 32),
      nonce: h.subarray(32, 44)
    };
  }

  // Pad to a 4KB boundary measured in UTF-8 bytes, so file size
  // does not reveal how many entries the vault holds.
  function padBytes(str) {
    const enc = new TextEncoder().encode(str);
    const target = Math.ceil((enc.length + 1) / PAD_BLOCK) * PAD_BLOCK;
    const out = new Uint8Array(target).fill(0x20); // space
    out.set(enc, 0);
    return out;
  }

  return {
    MAGIC, HEADER_LEN, PAD_BLOCK, VERSION,
    KDF_ARGON2ID, KDF_PBKDF2, CIPHER_AES_GCM,
    buildHeader, parseHeader, padBytes
  };
})();
