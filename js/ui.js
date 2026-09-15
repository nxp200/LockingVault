/* ui.js — DOM rendering only. No crypto, no file access.
 * Entry text is set through textContent throughout, so a stored
 * title or note can never become markup.
 */
window.LV = window.LV || {};

LV.ui = (function () {
  const TOAST_GAP = 22; // matches the toast's resting offset in app.css

  const $ = function (id) { return document.getElementById(id); };

  function toast(text) {
    const t = $('toast');
    t.textContent = text;

    // Sit below the sticky top bar rather than on top of it, so the
    // toast never covers the add and lock buttons. The bar only exists
    // in the unlocked state and its offsetParent is null while hidden,
    // so the sealed screen keeps the toast at the top of the viewport.
    const bar = document.querySelector('.bar');
    const drop = (bar && bar.offsetParent !== null)
      ? Math.round(bar.getBoundingClientRect().height)
      : 0;
    t.style.top = (drop + TOAST_GAP) + 'px';

    t.classList.add('on');
    clearTimeout(t._t);
    t._t = setTimeout(function () { t.classList.remove('on'); }, 1900);
  }

  function showStage(which) {
    $('stage-choose').hidden = which !== 'choose';
    $('stage-unlock').hidden = which !== 'unlock';
    $('stage-new').hidden = which !== 'new';
  }

  function showSealed() {
    // Locking drops the decrypted model, but the DOM keeps whatever was
    // last rendered from it. Without this the entry list still holds
    // every plaintext secret after an idle lock — hidden, but sitting in
    // the document — and the generated passphrase likewise. Clear both
    // so "plaintext lives in memory only" stays true of the page too.
    closeSheet();
    $('list').innerHTML = '';
    $('gen').innerHTML = '';
    $('n').textContent = '0';
    $('nlabel').textContent = 'entries';

    $('vault').style.display = 'none';
    $('seal').style.display = 'flex';
    document.body.classList.remove('open');
    $('pp').value = '';
    $('confirm').value = '';
    $('m-unlock').textContent = '';
    $('m-new').textContent = '';
    showStage('choose');
  }

  function showVault() {
    document.body.classList.add('open');
    $('seal').style.display = 'none';
    $('vault').style.display = 'flex';
  }

  function renderPhrase(words) {
    const box = $('gen');
    box.innerHTML = '';
    words.forEach(function (w, i) {
      const b = document.createElement('b');
      b.textContent = w; // textContent, never innerHTML
      box.appendChild(b);
      if (i < words.length - 1) box.appendChild(document.createTextNode(' '));
    });
  }

  function renderEntries(entries, handlers) {
    const list = $('list');
    $('n').textContent = entries.length;
    $('nlabel').textContent = entries.length === 1 ? 'entry' : 'entries';
    list.innerHTML = '';

    if (!entries.length) {
      const p = document.createElement('p');
      p.className = 'empty';
      p.textContent = 'Nothing stored yet. Tap + to add your first password.';
      list.appendChild(p);
      return;
    }

    entries.forEach(function (entry) {
      const el = document.createElement('div');
      el.className = 'entry';

      const h = document.createElement('h3');
      h.textContent = entry.title || 'Untitled';
      el.appendChild(h);

      if (entry.username) {
        const u = document.createElement('div');
        u.className = 'user';
        u.textContent = entry.username;
        el.appendChild(u);
      }

      const s = document.createElement('div');
      s.className = 'secret';
      s.textContent = entry.secret || '';
      el.appendChild(s);

      const acts = document.createElement('div');
      acts.className = 'acts';

      const reveal = document.createElement('button');
      reveal.textContent = 'Reveal';
      reveal.onclick = function () {
        reveal.textContent = el.classList.toggle('shown') ? 'Hide' : 'Reveal';
      };

      const copy = document.createElement('button');
      copy.textContent = 'Copy';
      copy.onclick = function () { handlers.copy(entry); };

      const edit = document.createElement('button');
      edit.textContent = 'Edit';
      edit.onclick = function () { handlers.edit(entry); };

      const del = document.createElement('button');
      del.className = 'del';
      del.textContent = 'Delete';
      del.onclick = function () { handlers.remove(entry); };

      acts.appendChild(reveal);
      acts.appendChild(copy);
      acts.appendChild(edit);
      acts.appendChild(del);
      el.appendChild(acts);
      list.appendChild(el);
    });
  }

  // One sheet serves both adding and editing. Pass an entry to load it
  // for editing, or nothing to start a blank one — same fields, same
  // save button, only the labels differ.
  const SHEET_FIELDS = {
    'e-title': 'title', 'e-user': 'username', 'e-secret': 'secret', 'e-url': 'url'
  };

  function openSheet(entry) {
    Object.keys(SHEET_FIELDS).forEach(function (id) {
      $(id).value = entry ? (entry[SHEET_FIELDS[id]] || '') : '';
    });
    $('sheet-title').textContent = entry ? 'Edit entry' : 'New entry';
    $('b-save-entry').textContent = entry ? 'Save changes' : 'Add entry';
    $('sheet').classList.add('on');
    $('e-title').focus();
  }

  function closeSheet() {
    // Clear the fields on the way out. They hold a plaintext secret,
    // and the sheet can be closed by the vault locking underneath it.
    Object.keys(SHEET_FIELDS).forEach(function (id) { $(id).value = ''; });
    $('sheet').classList.remove('on');
  }

  function setBuildInfo(hasArgon2) {
    $('verline').textContent = hasArgon2 ? 'VLT1 · argon2id' : 'VLT1 · pbkdf2';
    $('kdfnote').textContent = hasArgon2
      ? 'Key derivation: Argon2id, 64 MiB. Files are written as format VLT1.'
      : 'Key derivation: PBKDF2-SHA256 at 600,000 iterations — a placeholder. '
      + 'Inline an Argon2id WASM build before you trust this with real passwords; '
      + 'the header already carries the parameters, so vaults made now stay readable.';
  }

  return {
    $, toast, showStage, showSealed, showVault,
    renderPhrase, renderEntries, openSheet, closeSheet, setBuildInfo
  };
})();
