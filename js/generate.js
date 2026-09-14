/* generate.js — passphrase and password generation.
 * All randomness comes from crypto.getRandomValues with rejection
 * sampling; a plain modulo would bias the low end of the wordlist
 * and quietly cost entropy on every vault created.
 */
window.LV = window.LV || {};

LV.generate = (function () {
  const PW_ALPHABET =
    'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+?';

  function secureIndex(max) {
    const limit = 65536 - (65536 % max); // 65536 % 7776 = 3328 discarded
    const buf = new Uint16Array(1);
    let v;
    do {
      crypto.getRandomValues(buf);
      v = buf[0];
    } while (v >= limit);
    return v % max;
  }

  // Words drawn from the 7776-word EFF long list, so each one is
  // log2(7776) = 12.925 bits. Eight words is 103.4 bits.
  //
  // This is the only security parameter that scales exponentially.
  // Raising the Argon2 memory cost multiplies an attacker's cost by a
  // constant; adding a word multiplies the search space by 7776. Change
  // this rather than the KDF parameters if the threat model grows.
  const WORD_COUNT = 8;

  function passphrase(wordCount) {
    const n = wordCount || WORD_COUNT;
    const out = [];
    for (let i = 0; i < n; i++) out.push(LV.WORDS[secureIndex(LV.WORDS.length)]);
    return out;
  }

  function password(length) {
    const n = length || 20;
    let out = '';
    for (let i = 0; i < n; i++) out += PW_ALPHABET[secureIndex(PW_ALPHABET.length)];
    return out;
  }

  return { WORD_COUNT, secureIndex, passphrase, password };
})();
