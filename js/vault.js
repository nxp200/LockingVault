/* vault.js — the decrypted model and its lifetime.
 * Plaintext and passphrase live here, in memory only, and are
 * dropped on lock. Nothing is written to localStorage or IndexedDB.
 */
window.LV = window.LV || {};

LV.vault = (function () {
  const IDLE_MS = 3 * 60 * 1000;

  let data = null;      // decrypted payload
  let phrase = null;    // master passphrase
  let pending = null;   // encrypted bytes awaiting unlock
  let idleTimer = null;
  let onIdleLock = null;

  const isOpen = function () { return data !== null; };
  const get = function () { return data; };
  const entries = function () { return data ? data.entries : []; };

  function touch() {
    data.updated = new Date().toISOString();
  }

  function resetIdle() {
    clearTimeout(idleTimer);
    if (!isOpen()) return;
    idleTimer = setTimeout(function () {
      lock();
      if (onIdleLock) onIdleLock();
    }, IDLE_MS);
  }

  function create(passphraseWords) {
    phrase = passphraseWords.join(' ');
    data = { v: 1, revision: 1, updated: new Date().toISOString(), entries: [] };
    resetIdle();
  }

  function adopt(decrypted, enteredPhrase) {
    data = decrypted;
    phrase = enteredPhrase;
    pending = null;
    resetIdle();
  }

  function lock() {
    data = null;
    phrase = null;
    pending = null;
    clearTimeout(idleTimer);
  }

  function addEntry(fields) {
    const now = new Date().toISOString();
    data.entries.push({
      id: crypto.randomUUID(),
      title: fields.title,
      username: fields.username || '',
      secret: fields.secret || '',
      url: fields.url || '',
      notes: '',
      tags: [],
      created: now,
      updated: now
    });
    touch();
  }

  // Same field handling as addEntry, so an entry written by one path
  // is shaped identically to one written by the other. created and id
  // are preserved; updated moves.
  function updateEntry(id, fields) {
    const entry = data.entries.find(function (e) { return e.id === id; });
    if (!entry) return false;
    entry.title = fields.title;
    entry.username = fields.username || '';
    entry.secret = fields.secret || '';
    entry.url = fields.url || '';
    entry.updated = new Date().toISOString();
    touch();
    return true;
  }

  function removeEntry(id) {
    data.entries = data.entries.filter(function (e) { return e.id !== id; });
    touch();
  }

  // Bumped on every save; this is what a sync layer would compare
  // to detect two devices writing over each other.
  function bumpRevision() {
    data.revision = (data.revision || 0) + 1;
    touch();
  }

  return {
    IDLE_MS, isOpen, get, entries,
    create, adopt, lock, addEntry, updateEntry, removeEntry, bumpRevision, resetIdle,
    setPending: function (b) { pending = b; },
    getPending: function () { return pending; },
    getPhrase: function () { return phrase; },
    onIdleLock: function (fn) { onIdleLock = fn; }
  };
})();
