# LockingVault — project handoff

Context transfer for continuing work in a new project. Covers what was
decided, why, what is built, what is deliberately unfinished, and the one
change that must happen before this holds real passwords.

The code is the zip already copied over: `lockingvault/`.

---

## 1. What this is

An offline password manager. All credentials live in a single encrypted
file that the user stores wherever they like — local disk, USB stick,
Google Drive. The app makes no network requests. There is no server, no
account, no sync service.

The storage location is untrusted by design. Google Drive holds an opaque
blob and learns nothing.

**Target platform:** Chrome on Android was the first client, but the
intent is platform independence. The strategy for that is to treat the
*file format as the spec* and the app as one of several possible readers.
Any language on any platform can implement the format. The browser app is
just the first implementation.

---

## 2. The design question that started it

The original ask: could a file be encrypted such that nobody can brute
force it in a reasonable timeframe with current technology?

Answer: yes, and the encryption is not the hard part. AES-256 and
XChaCha20 keys are not brute-forceable — 2²⁵⁶ is beyond physics. Security
collapses entirely onto two things:

1. **Master password entropy** — the only real attack surface
2. **KDF cost** — how expensive each guess is when an attacker holds the
   file offline with unlimited time

Everything else in this project follows from those two.

### How the master secret was settled

The progression through the conversation, with the reasoning preserved
because it will come up again:

| Proposal | Entropy | Verdict |
|---|---|---|
| 8 chars, human-chosen | ~28 bits | Falls in minutes. Rejected. |
| 8 chars, random | ~53 bits | Decades, but erodes with hardware. Thin. |
| 12 chars, human-chosen | ~30–40 bits | Hours to years. Rejected. |
| 12 chars, random | ~79 bits | Sound, but painful to type on a phone. |
| **6-word diceware** | **77.5 bits** | **Chosen.** |

Six words from the EFF long list (7776 words) gives 7776⁶ ≈ 2⁷⁷·⁵. That is
statistically equivalent to random 12 characters, far easier to remember,
and much harder to fat-finger on a phone keyboard.

The critical insight, worth restating because it is counterintuitive: the
*character count is not the security parameter*. `Sydney2024!` and a random
12-char string are the same length and differ by roughly 40 bits, because
crackers model how humans choose. This is why **the app generates the
passphrase and does not accept a user-supplied one.** A password manager
can reasonably insist on this, since the master secret is the only one the
user ever has to memorise.

A password + keyfile scheme was considered as an alternative (small random
file stored separately from the vault, both needed to decrypt). Rejected as
unnecessary once diceware was chosen, but it remains the fallback if a
shorter memorised secret is ever wanted.

> Entropy-to-time estimates above are rough. Sanity-check against current
> cracking benchmarks before making any public claim about them.

---

## 3. The file format (VLT1)

```
offset  size  field
0       4     magic "VLT1"
4       1     format version
5       1     KDF id (1 = Argon2id, 2 = PBKDF2-SHA256)
6       4     memory cost in KiB (uint32 BE, 0 for PBKDF2)
10      4     iterations (uint32 BE)
14      1     parallelism
15      1     cipher id (1 = AES-256-GCM)
16      16    salt
32      12    nonce
44      16    reserved (zeroed)
60      1     header length
61      ..    ciphertext + 16-byte GCM tag
```

Four properties of this layout matter and should not be casually changed:

**The header is passed as AEAD additional data.** Without this, an attacker
could rewrite the memory cost down to something trivially crackable and
hand the file back. With it, authentication fails first. There is a test
for exactly this (`rejects downgraded KDF params`).

**KDF parameters live in the file, not the code.** This is what makes the
format future-proof: costs can be raised later, and old vaults still open
because the reader uses whatever the file declares.

**Fresh 12-byte nonce on every save.** Reusing a nonce with the same key
breaks AES-GCM catastrophically — not gracefully. This is the single
easiest way to destroy the whole scheme.

**Payload padded to a 4 KB boundary**, measured in UTF-8 bytes, so file
size does not reveal roughly how many entries the vault holds.

Plaintext payload:

```json
{
  "v": 1,
  "revision": 42,
  "updated": "2026-09-13T04:12:00Z",
  "entries": [{
    "id": "uuid", "title": "GitHub", "username": "nam",
    "secret": "...", "url": "https://github.com",
    "notes": "", "tags": [],
    "created": "...", "updated": "..."
  }]
}
```

No compression. Compressing before encrypting leaks information through
ciphertext length.

---

## 4. The Argon2 swap — the one critical outstanding change

This is the thing that must happen before the app holds anything real.

### What the problem is

Deriving the encryption key from a passphrase requires a **key derivation
function (KDF)**. Its whole job is to be slow and expensive, so that an
attacker who has stolen the vault file and is guessing passphrases offline
gets very few attempts per second.

The app currently uses **PBKDF2-SHA256 at 600,000 iterations**. PBKDF2 does
one thing: run SHA-256 over and over. It is slow in *time* but needs almost
no *memory*.

That is the weakness. A GPU has thousands of small cores, and since each
PBKDF2 guess needs only a few hundred bytes, a single graphics card can run
tens of thousands of guesses in parallel. Purpose-built ASIC hardware is
worse still. The attacker's advantage over your phone is enormous.

**Argon2id** is designed to remove that advantage. It deliberately requires
a large block of memory — say 64 MiB — for *every single guess*. A GPU with
16 GB of memory can therefore only run about 250 guesses at once instead of
tens of thousands. The attacker now has to buy memory, not just cores, and
memory is the expensive part. It won the Password Hashing Competition in
2015 and is the current standard recommendation. ("id" is the hybrid
variant, combining resistance to side-channel attacks and to GPU attacks.)

**So why isn't it already in there?** Because WebCrypto — the browser's
built-in `crypto.subtle` — provides PBKDF2 but does *not* provide Argon2 or
scrypt. A browser app has to bring its own, compiled to WebAssembly. That
WASM build could not be fetched while the app was being written, so PBKDF2
went in as a clearly-labelled placeholder and the lock screen says so.

### What the swap actually involves

The code is already structured for it. `js/crypto.js` opens with:

```js
const HAS_ARGON2 = typeof window.argon2 !== 'undefined';

const DEFAULT_PARAMS = HAS_ARGON2
  ? { kdf: F.KDF_ARGON2ID, memoryKiB: 65536, iterations: 3, parallelism: 1 }
  : { kdf: F.KDF_PBKDF2,   memoryKiB: 0,     iterations: 600000, parallelism: 1 };
```

So the steps are:

1. **Get an audited Argon2 WASM build.** `argon2-browser` and `hash-wasm`
   are the usual candidates. Check it is maintained and has had eyes on it
   — this is the component protecting everything else.
2. **Load it before `js/crypto.js`** in `index.html`. For the single-file
   bundle, inline the `.wasm` as base64 so `dist/lockingvault.html` stays
   one file; `build.js` will need a small addition to do that.
3. **Verify the API signature matches.** This is the most likely thing to
   break. The code currently assumes the `argon2-browser` shape:
   ```js
   argon2.hash({ pass, salt, time, mem, parallelism, hashLen, type })
   ```
   `hash-wasm` uses different parameter names entirely (`password`,
   `iterations`, `memorySize`, `hashLength`). Check yours and adjust
   `deriveKey()` accordingly. Confirm `salt` is accepted as a `Uint8Array`
   and that the returned `.hash` is a `Uint8Array` of 32 bytes.
4. **Do not delete the PBKDF2 branch.** Vaults written today record
   `kdf = 0x02` and must keep opening. The `parseHeader` check already
   accepts both.
5. **Benchmark on the oldest phone you care about**, not a flagship. Target
   roughly one second to unlock. Start at m=64 MiB, t=3, p=1. If it is too
   slow, **reduce iterations before reducing memory** — memory is the
   security-relevant knob, and dropping it is what hands the GPU advantage
   back.

### Migrating existing vaults

Pleasantly, nothing special is needed. `encryptVault` falls back to
`DEFAULT_PARAMS` when no params are passed, and the save path passes none.
So once Argon2 is present: **unlock an old vault, hit save, and it is
re-encrypted under Argon2id.** The new header records `kdf = 0x01`.

---

## 5. Code structure

```
index.html          markup, and the script load order
css/app.css         all styling
js/wordlist.js      EFF long list, 7776 words
js/format.js        VLT1 header layout, build and parse
js/crypto.js        key derivation, encrypt, decrypt
js/generate.js      passphrase and password generation
js/storage.js       file open and save
js/vault.js         decrypted model, entry ops, idle lock
js/ui.js            DOM rendering only
js/app.js           wiring
build.js            inlines everything to dist/lockingvault.html
test.mjs            16 headless checks
README.md
```

Each file attaches to a single `LV` global. **Load order matters** and is
declared in `index.html`: `format` before `crypto`, `wordlist` before
`generate`.

The split runs along what each part is permitted to touch. `ui.js` never
sees a passphrase; `crypto.js` never sees a DOM element. The payoff is that
the Argon2 swap is one function in one file.

**Classic `<script>` tags, not ES modules.** This is deliberate: `import`
is blocked over `file://` by CORS, so modules would mean running a local
server just to open your own vault. That defeats the premise. `build.js`
produces the single-file bundle for moving onto a phone.

---

## 6. Runtime security properties already implemented

- Plaintext exists in memory only — no localStorage, no IndexedDB, no cache
- Vault auto-locks after 3 minutes idle
- Copied passwords cleared from clipboard after 20 seconds
- Failed unlock reports **one** message whether the passphrase was wrong or
  the file was tampered with — distinguishing them leaks information
- AES-GCM verifies the auth tag before releasing any plaintext
- Entry text is rendered via `textContent` throughout, so a stored title or
  note can never become markup
- Passphrase confirmation step before a vault is created, since losing it
  means the vault is gone

---

## 7. Gotchas discovered the hard way

**Four EFF words contain hyphens** — `drop-down`, `felt-tip`, `t-shirt`,
`yo-yo`. This permanently rules out hyphen-as-separator in passphrases.
Words are joined with spaces only. Found before it could corrupt anyone's
ability to open a vault.

**Padding must be computed on UTF-8 byte length, not JS string length.**
The first implementation used string length; non-ASCII entries then broke
the 4 KB quantisation. Caught by a test with an accented entry.

**`canonical()` is load-bearing.** It NFKC-normalises, lowercases and
collapses whitespace before the phrase reaches the KDF. A single differing
byte means the key does not derive and the vault will not open. Users will
type their phrase with odd spacing and capitalisation. Normalise hard at
both generation and unlock.

**In a browser, `window` *is* the global object**, so `window.LV = ...`
also defines a bare `LV`. A naive Node test sandbox does not replicate
this; `test.mjs` points `window` at the sandbox itself to match.

---

## 8. Platform constraints

**File System Access API** (`showSaveFilePicker`, persistent file handles,
in-place saves) is Chromium-only. Firefox's vendor position is negative and
Safari's is opposed on security grounds — it is unlikely to become a
standard in its current form. Chrome on Android only got it in v132
(January 2025). Everywhere else, saving falls back to a download, which for
a vault means an accumulating pile of `my(4).vault` files. This is the real
platform-independence problem and it is a storage-layer issue, not a format
one.

**Google Drive** is workable via the Drive REST API with OAuth PKCE, using
the `drive.file` scope so the app can only touch files the user explicitly
picks — a good trust story. But OAuth needs a registered client ID and a
real HTTPS origin, so the app would have to be *hosted* (static host is
fine, still no backend) rather than opened from `file://`. Not yet started.

---

## 9. Open work, in rough priority order

1. **Argon2id swap** (section 4) — blocking for real use
2. **Sync conflict handling.** Two devices that both decrypt and save will
   silently overwrite each other, losing entries with no error. `revision`
   in the payload increments on every save and is the hook for detecting
   this, but nothing reads it yet. Google Drive exposes revision IDs for
   the remote side. This was flagged early as the thing most likely to bite
   in practice, ahead of anything cryptographic.
3. **Editing entries** — currently add and delete only
4. Search / filter
5. Import and export (competitor formats, CSV)
6. Google Drive storage backend
7. Readers for other platforms, to prove the format travels

---

## 10. Things to verify rather than trust

- Entropy-to-cracking-time estimates throughout — sanity-check against
  current benchmarks before relying on them
- The Argon2 WASM build's API signature against whatever build is chosen
- Argon2 parameter timing on a real mid-range Android device
- That the wordlist is still exactly 7776 unique entries if ever
  regenerated — a truncated or deduplicated list silently reduces entropy
  below the advertised 77.5 bits. `test.mjs` checks this.

---

## 11. Tests

```bash
node test.mjs
```

16 checks covering the wordlist, generation and index distribution,
round-tripping with Unicode entries, whitespace and case tolerance, and
rejection of wrong passphrases, downgraded KDF parameters, flipped
ciphertext bits and corrupted magic bytes. They load the real source files,
so they test what ships. All passing.

```bash
node build.js    # -> dist/lockingvault.html, ~91 KB
```
