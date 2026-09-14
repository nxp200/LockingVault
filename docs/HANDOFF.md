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

## 4. Key derivation — Argon2id (done, 2026-09-14)

This was the one blocking item. It is now in.

### Why it mattered

The key is derived from the passphrase by a KDF, whose only job is to
be slow, because an attacker holding the stolen file guesses offline
with no rate limit. The app previously used **PBKDF2-SHA256 at 600,000
iterations** as a labelled placeholder. PBKDF2 is slow in time but
needs almost no memory, so a GPU runs tens of thousands of guesses in
parallel and the attacker's advantage over a phone is enormous.

**Argon2id** forces every guess to hold a large block of memory — 64
MiB here — for its whole duration. A 16 GB card can then hold only a
few hundred guesses at once. The cost shifts from cores, which are
cheap, to memory, which is not.

It was not in originally because WebCrypto does not provide Argon2 and
the WASM build could not be fetched at the time.

### What was chosen and why

**hash-wasm 4.12.0**, `dist/argon2.umd.min.js`, 29 KB, vendored at
`vendor/hash-wasm-argon2.umd.min.js`.

It ships the `.wasm` inlined as base64 and makes no `fetch`, `XHR` or
`require` call at runtime. That is the deciding property: anything that
loads its `.wasm` as a separate file is blocked by CORS over `file://`,
which would have meant running a server to open your own vault. It is
also actively maintained, which `argon2-browser` (last release 2021) is
not.

`js/argon2.js` adapts it to the `window.argon2.hash({ pass, salt, time,
mem, parallelism, hashLen, type })` shape `crypto.js` already expected,
so **`js/crypto.js` was not modified at all**. Swapping the vendor
library later is a change to the adapter alone.

Load order in `index.html` is vendor, adapter, then `js/crypto.js`,
which reads `window.argon2` at load time.

### Parameters

m = 64 MiB, t = 3, p = 1, 32-byte output — the existing
`DEFAULT_PARAMS`, unchanged. Measured at **~117 ms per derivation** on
Nam's Mac. That is well under the ~1 s target, but the Mac is not the
constraint: a mid-range Android phone in a browser will be several
times slower and is where this has to be timed. **Not yet measured on a
phone.** If it has to come down there, reduce iterations and leave
memory alone — memory is what removes the GPU advantage.

### Verification

The vendored build was cross-checked against the Argon2 **reference
implementation** (libargon2 via `argon2-cffi`) on a fixed input: both
produce `f7b06f51…504c0`, byte for byte. That digest is now a
known-answer test in `test.mjs`, so a vendor build that is present but
subtly wrong — wrong variant, wrong version, parameters quietly ignored
— fails loudly instead of writing vaults no other reader can open.

### Migration

Nothing special, as designed. `encryptVault` falls back to
`DEFAULT_PARAMS` when passed none, and the save path passes none. So an
old PBKDF2 vault opens, and the next save re-encrypts it under
Argon2id with `kdf = 0x01`. The PBKDF2 branch stays in place for vaults
that have not been re-saved yet. There is a test covering exactly this
round trip.

### Still to check on a real device

- Timing on a mid-range Android phone (above)
- That a 64 MiB WASM allocation actually succeeds on a low-RAM phone
  and under iOS Safari's WASM memory limits — a failure here surfaces
  as the unlock throwing rather than as a wrong answer, but it has not
  been exercised in a real browser yet, only headlessly in Node

## 5. Code structure

```
index.html          markup, and the script load order
css/app.css         all styling
vendor/…argon2…js   hash-wasm argon2 build, wasm inlined as base64
js/argon2.js        adapter: vendor API -> window.argon2
js/wordlist.js      EFF long list, 7776 words
js/format.js        VLT1 header layout, build and parse
js/crypto.js        key derivation, encrypt, decrypt
js/generate.js      passphrase and password generation
js/storage.js       file open and save
js/vault.js         decrypted model, entry ops, idle lock
js/ui.js            DOM rendering only
js/app.js           wiring
build.js            inlines everything to dist/lockingvault.html
test.mjs            24 headless checks
README.md
```

Each file attaches to a single `LV` global. **Load order matters** and is
declared in `index.html`: vendor and `argon2` before `crypto`, `format`
before `crypto`, `wordlist` before `generate`.

The split runs along what each part is permitted to touch. `ui.js` never
sees a passphrase; `crypto.js` never sees a DOM element. The payoff was that
the Argon2 swap touched one new file and no existing logic.

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

1. ~~Argon2id swap~~ — done, see section 4. Remaining: time it on a
   real mid-range phone and confirm the 64 MiB allocation succeeds
   there.
2. **Sync conflict handling.** Two devices that both decrypt and save
   will silently overwrite each other, losing entries with no error.
   `revision` in the payload increments on every save and is the hook
   for detecting this, but nothing reads it yet. Google Drive exposes
   revision IDs for the remote side. This was flagged early as the
   thing most likely to bite in practice, ahead of anything
   cryptographic — and with Argon2 done it is now the top risk.
3. **Editing entries** — currently add and delete only
4. Search / filter
5. Import and export (competitor formats, CSV)
6. Google Drive storage backend
7. Readers for other platforms, to prove the format travels

## 10. Things to verify rather than trust

- Entropy-to-cracking-time estimates throughout — sanity-check against
  current benchmarks before relying on them
- ~~The Argon2 WASM build's API signature~~ — done; cross-checked against
  the reference implementation and pinned by a known-answer test
- Argon2 parameter timing on a real mid-range Android device — still
  outstanding, only measured on a Mac (~117 ms)
- That the wordlist is still exactly 7776 unique entries if ever
  regenerated — a truncated or deduplicated list silently reduces entropy
  below the advertised 77.5 bits. `test.mjs` checks this.

---

## 11. Tests

```bash
node test.mjs
```

24 checks covering the wordlist, generation and index distribution, the
Argon2 reference vector, round-tripping with Unicode entries, whitespace
and case tolerance, migration of an old PBKDF2 vault to Argon2id, and
rejection of wrong passphrases, downgraded memory cost, a swapped KDF id,
flipped ciphertext bits and corrupted magic bytes. They load the real
source files, so they test what ships. All passing.

Note: the downgrade test now strips the *memory* cost rather than raising
the iteration count. Memory is the parameter an attacker actually wants
to remove, and raising Argon2 iterations to 1000 would have made the test
itself take minutes.

```bash
node build.js    # -> dist/lockingvault.html, ~122 KB
```
