# LockingVault

An offline password manager. Everything lives in one encrypted file
that you keep wherever you like — local disk, a USB stick, Google
Drive. Nothing is uploaded, and the app makes no network requests at
all.

## Running it

Open `index.html` in a browser. No build step, no server, no
dependencies. `file://` works because the scripts are classic
`<script>` tags rather than ES modules — modules are blocked over
`file://` by CORS, which would have meant running a server just to
open your own passwords.

To make the portable version:

    node build.js        # -> dist/lockingvault.html, one file, ~122 KB

The bundle is what you put on a phone. The split tree is what you
edit.

## Layout

    index.html          markup and script order
    css/app.css         all styling
    vendor/             hash-wasm argon2 build, wasm inlined as base64
    js/argon2.js        adapter: vendor API -> window.argon2
    js/wordlist.js      EFF long list, 7776 words
    js/format.js        VLT1 header layout, parse and build
    js/crypto.js        key derivation, encrypt, decrypt
    js/generate.js      passphrase and password generation
    js/storage.js       file open and save
    js/vault.js         decrypted model, idle lock
    js/ui.js            DOM rendering
    js/app.js           wiring
    build.js            inliner
    test.mjs            headless checks

Each file attaches to a single `LV` global. Load order is declared in
`index.html` and matters: the vendor build and `js/argon2.js` before
`crypto`, `format` before `crypto`, `wordlist` before `generate`.
`crypto.js` decides at load time whether Argon2 is available, so
anything arriving later is ignored.

## The file format

    offset  size  field
    0       4     magic "VLT1"
    4       1     format version
    5       1     KDF id (1 = Argon2id, 2 = PBKDF2-SHA256)
    6       4     memory cost in KiB
    10      4     iterations
    14      1     parallelism
    15      1     cipher id (1 = AES-256-GCM)
    16      16    salt
    32      12    nonce
    44      16    reserved
    60      1     header length
    61      ..    ciphertext + 16-byte GCM tag

The header is passed as AEAD additional data, so an attacker cannot
rewrite the memory cost down to something crackable and hand the file
back — authentication fails first.

Because the parameters live in the file rather than in the code, you
can raise costs later and old vaults still open.

## Security notes

The master passphrase is eight words from the EFF long list, which is
103.4 bits. The app generates it and will not accept one you invent,
because a chosen phrase is worth a fraction of that against a cracker
that knows how people choose words.

Word count, not KDF cost, is the parameter that matters. Each word
multiplies the search space by 7776; doubling the Argon2 memory cost
merely doubles it. If the threat model ever grows, add a word — it
costs nothing at unlock time and cannot lock you out of a device the
way a larger memory cost can.

The flip side is that there is no recovery. A phrase this strong is
worthless if it is lost, and losing it is now the most likely way to
lose the vault — far likelier than anyone breaking it.

Four words in the list contain hyphens (`drop-down`, `felt-tip`,
`t-shirt`, `yo-yo`). Words are therefore joined with spaces only, and
a hyphen can never be treated as a separator. `canonical()` in
`crypto.js` lowercases and collapses whitespace so that a phrase typed
with odd spacing still derives the same key.

The payload is padded to a 4 KB boundary so file size does not reveal
how many entries the vault holds.

A fresh 12-byte nonce is generated on every save. Reusing one with the
same key breaks AES-GCM badly.

Plaintext exists only in memory. There is no localStorage, no
IndexedDB, no cache. The vault locks after three minutes idle, and
copied passwords are cleared from the clipboard after twenty seconds.

Failed unlocks report one message whether the passphrase was wrong or
the file was tampered with. Distinguishing them would leak.

### Key derivation

Argon2id at 64 MiB, 3 passes, parallelism 1. WebCrypto does not
provide Argon2, so the app carries its own WASM build (hash-wasm) with
the `.wasm` inlined as base64 — no fetch, which is what lets the whole
thing run from `file://`.

`js/argon2.js` normalises that library to the `window.argon2.hash(...)`
shape `crypto.js` expects. Swapping the vendor build later is a change
to that one adapter.

Memory cost is the security-relevant knob: it is what stops a GPU from
running thousands of guesses in parallel, because each guess has to own
64 MiB for its duration. If the parameters need to come down on a slow
device, reduce iterations first and leave memory alone.

If the vendor build is missing the app falls back to PBKDF2-SHA256 at
600,000 iterations and says so on the lock screen. Vaults written under
either KDF record which one they used and keep opening. An old PBKDF2
vault migrates the moment you unlock it and save — the save path
re-derives under the current defaults.

The test suite includes a known-answer test against a digest produced
by the Argon2 reference implementation, so a vendor build that is
present but subtly wrong fails loudly rather than writing vaults no
other reader can open.

Benchmark on the oldest phone you care about, not a flagship, and aim
for about a second to unlock.

## Tests

    node test.mjs

Twenty-four checks over the wordlist, generation, the Argon2 reference
vector, round-tripping with Unicode, whitespace tolerance, migration of
an old PBKDF2 vault, and rejection of wrong passphrases, downgraded
memory cost, a swapped KDF id, flipped ciphertext bits and corrupted
magic. They load the real source files, so they test what ships.

## Not done yet

Sync conflict handling. Two devices that both decrypt and save will
silently overwrite each other. `revision` in the payload increments on
every save and is the hook for detecting it, but nothing reads it yet.

Editing entries, search, and import or export are also absent.
