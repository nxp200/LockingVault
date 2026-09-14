/* ui.js — DOM rendering only. No crypto, no file access.
 * Entry text is set through textContent throughout, so a stored
 * title or note can never become markup.
 */
window.LV = window.LV || {};

LV.ui = (function () {
  const $ = function (id) { return document.getElementById(id); };

  function toast(text) {
    const t = $('toast');
    t.textContent = text;
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
      b.textContent = w;
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

      const del = document.createElement('button');
      del.className = 'del';
      del.textContent = 'Delete';
      del.onclick = function () { handlers.remove(entry); };

      acts.appendChild(reveal);
      acts.appendChild(copy);
      acts.appendChild(del);
      el.appendChild(acts);
      list.appendChild(el);
    });
  }

  function openSheet() {
    ['e-title', 'e-user', 'e-secret', 'e-url'].forEach(function (id) { $(id).value = ''; });
    $('sheet').classList.add('on');
    $('e-title').focus();
  }

  function closeSheet() { $('sheet').classList.remove('on'); }

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
