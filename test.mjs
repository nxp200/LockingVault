/* test.mjs — headless checks on the crypto core and wordlist.
 * Loads the real source files, so these test what ships.
 *   node test.mjs
 */
import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// In a browser, window IS the global object, so `window.LV = ...` also
// defines a bare `LV`. Point window at the sandbox itself to match.
const sandbox = { crypto: webcrypto, TextEncoder, TextDecoder, console };
sandbox.window = sandbox;
vm.createContext(sandbox);

// The vendored Argon2 WASM build loads first, exactly as index.html
// orders it: vendor, adapter, then crypto.js, which decides at load
// time whether Argon2 is available.
vm.runInContext(readFileSync('vendor/hash-wasm-argon2.umd.min.js', 'utf8'),
  sandbox, { filename: 'argon2-wasm' });

for (const f of ['argon2', 'wordlist', 'format', 'crypto', 'generate']) {
  vm.runInContext(readFileSync(`js/${f}.js`, 'utf8'), sandbox, { filename: f });
}
const LV = sandbox.LV;

let pass = 0, fail = 0;
const check = (name, ok) => { ok ? pass++ : fail++; console.log((ok ? '  ok  ' : 'FAIL  ') + name); };

// wordlist
check('7776 words', LV.WORDS.length === 7776);
check('all unique', new Set(LV.WORDS).size === 7776);
check('hyphenated words present', LV.WORDS.includes('t-shirt') && LV.WORDS.includes('yo-yo'));

// generation
const p = LV.generate.passphrase(6);
check('passphrase is 6 words', p.length === 6);
check('words come from the list', p.every(w => LV.WORDS.includes(w)));
const spread = new Set();
for (let i = 0; i < 2000; i++) spread.add(LV.generate.secureIndex(7776));
check('secureIndex spreads across range', spread.size > 1500);
check('password length honoured', LV.generate.password(20).length === 20);

// argon2
check('argon2 backend loaded', LV.crypto.HAS_ARGON2 === true);
check('argon2id is the default KDF',
  LV.crypto.DEFAULT_PARAMS.kdf === LV.format.KDF_ARGON2ID &&
  LV.crypto.DEFAULT_PARAMS.memoryKiB === 65536 &&
  LV.crypto.DEFAULT_PARAMS.iterations === 3);

// Known-answer test. This digest came from the Argon2 reference
// implementation (libargon2 via argon2-cffi), computed independently of
// this build. A vendor library that is present but subtly wrong — wrong
// variant, wrong version, parameters silently ignored — fails here
// rather than quietly producing vaults nobody else can open.
const KAT = 'f7b06f514a6318d1046977ade4d962834a4f5b627f77a04e5f976506c56504c0';
const kat = await sandbox.window.argon2.hash({
  pass: 'correct horse battery staple', salt: 'lockingvault-kat',
  time: 3, mem: 65536, parallelism: 1, hashLen: 32,
  type: sandbox.window.argon2.ArgonType.Argon2id
});
check('matches the argon2 reference implementation',
  Buffer.from(kat.hash).toString('hex') === KAT);

// crypto round trip
const phrase = 'trombone wildcat abacus yo-yo t-shirt rekindle';
const data = {
  v: 1, revision: 1, updated: new Date().toISOString(),
  entries: [
    { id: 'a', title: 'GitHub', username: 'nam', secret: 'K7#mQ2xLp!9v', url: 'https://github.com' },
    { id: 'b', title: 'AWS', username: 'root', secret: '«unicode ✓ ümlaut»', url: '' }
  ]
};

const bytes = await LV.crypto.encryptVault(data, phrase);
check('header magic is VLT1', String.fromCharCode(...bytes.subarray(0, 4)) === 'VLT1');
check('payload padded to 4KB', (bytes.length - LV.format.HEADER_LEN - 16) % 4096 === 0);
check('header records argon2id', bytes[5] === LV.format.KDF_ARGON2ID);

const back = await LV.crypto.decryptVault(bytes, phrase);
check('round trips intact', JSON.stringify(back.data) === JSON.stringify(data));

const loose = await LV.crypto.decryptVault(bytes, '  Trombone   WILDCAT abacus yo-yo t-shirt rekindle ');
check('tolerates case and spacing', JSON.stringify(loose.data) === JSON.stringify(data));

const rejects = async (name, mutate, key) => {
  const b = bytes.slice();
  if (mutate) mutate(b);
  try { await LV.crypto.decryptVault(b, key || phrase); check(name, false); }
  catch (e) { check(name, true); }
};
await rejects('rejects wrong passphrase', null, 'wrong words entirely here now please');
await rejects('rejects downgraded memory cost', b => new DataView(b.buffer).setUint32(6, 8));
await rejects('rejects swapped KDF id', b => { b[5] = LV.format.KDF_PBKDF2; });
await rejects('rejects flipped ciphertext bit', b => { b[LV.format.HEADER_LEN + 5] ^= 0xff; });
await rejects('rejects corrupted magic', b => { b[0] = 0x58; });

// a vault written before argon2 landed must keep opening, and must
// migrate on the next save
const legacyParams = { kdf: LV.format.KDF_PBKDF2, memoryKiB: 0, iterations: 600000, parallelism: 1 };
const legacy = await LV.crypto.encryptVault(data, phrase, legacyParams);
check('legacy vault records pbkdf2', legacy[5] === LV.format.KDF_PBKDF2);
const reopened = await LV.crypto.decryptVault(legacy, phrase);
check('legacy pbkdf2 vault still opens', JSON.stringify(reopened.data) === JSON.stringify(data));
const resaved = await LV.crypto.encryptVault(reopened.data, phrase);
check('resaving migrates to argon2id', resaved[5] === LV.format.KDF_ARGON2ID);

// nonce must never repeat
const fast = { ...LV.crypto.DEFAULT_PARAMS, iterations: 1, memoryKiB: 1024 };
const nonces = new Set();
for (let i = 0; i < 5; i++) {
  const b = await LV.crypto.encryptVault(data, phrase, fast);
  nonces.add(Buffer.from(b.subarray(32, 44)).toString('hex'));
}
check('fresh nonce every save', nonces.size === 5);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
