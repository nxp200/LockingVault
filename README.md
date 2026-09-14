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

    node build.js        # -> dist/lockingvault.html, one file, ~91 KB

The bundle is what you put on a phone. The split tree is what you
edit.

## Layout

    index.html          markup and script order
    css/app.css         all styling
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
`index.html` and matters: `format` before `crypto`, `wordlist` before
`generate`.

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

The master passphrase is six words from the EFF long list, which is
77.5 bits. The app generates it and will not accept one you invent,
because a chosen phrase is worth a fraction of that against a cracker
that knows how people choose words.

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

### The Argon2 gap

Argon2id is what this format wants, and WebCrypto does not provide it.
If `window.argon2` is present the app uses it; otherwise it falls back
to PBKDF2-SHA256 at 600,000 iterations and says so on the lock screen.

PBKDF2 is not memory-hard, so a GPU farm attacks it far more
efficiently. Before trusting this with real passwords, inline an
audited Argon2 WASM build and load it ahead of `js/crypto.js`. Vaults
written now record `kdf = 2` and keep opening either way.

Benchmark the parameters on the oldest phone you care about. Aim for
about one second to unlock.

## Tests

    node test.mjs

Sixteen checks over the wordlist, generation, round-tripping with
Unicode, whitespace tolerance, and rejection of wrong passphrases,
downgraded KDF parameters, flipped ciphertext bits and corrupted
magic. They load the real source files, so they test what ships.

## Not done yet

Sync conflict handling. Two devices that both decrypt and save will
silently overwrite each other. `revision` in the payload increments on
every save and is the hook for detecting it, but nothing reads it yet.

Editing entries, search, and import or export are also absent.
