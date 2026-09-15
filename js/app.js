/* app.js — wiring. Owns no crypto and touches no bytes directly;
 * it moves things between the model, the storage layer and the DOM.
 */
(function () {
  const ui = LV.ui, V = LV.vault, S = LV.storage, C = LV.crypto, G = LV.generate;
  const $ = ui.$;

  let candidate = [];           // generated passphrase awaiting confirmation
  let editingId = null;         // entry open in the sheet, or null when adding
  const CLIPBOARD_CLEAR_MS = 20000;

  // Both the + button and an entry's Edit button come through here, so
  // the sheet's state and the model's are set in one place.
  function openEntrySheet(entry) {
    editingId = entry ? entry.id : null;
    ui.openSheet(entry);
  }

  function closeEntrySheet() {
    editingId = null;
    ui.closeSheet();
  }

  function refresh() {
    ui.renderEntries(V.entries(), {
      copy: async function (entry) {
        try {
          await navigator.clipboard.writeText(entry.secret || '');
          ui.toast('Copied. Clipboard clears in 20s.');
          setTimeout(function () {
            navigator.clipboard.writeText('').catch(function () {});
          }, CLIPBOARD_CLEAR_MS);
        } catch (e) {
          ui.toast('Clipboard blocked by the browser');
        }
      },
      edit: function (entry) {
        openEntrySheet(entry);
      },
      remove: function (entry) {
        V.removeEntry(entry.id);
        refresh();
        ui.toast('Deleted. Save to keep the change.');
      }
    });
  }

  function enterVault() {
    ui.showVault();
    refresh();
    V.resetIdle();
  }

  function lock(message) {
    editingId = null;
    V.lock();
    ui.showSealed();
    if (message) ui.toast(message);
  }

  /* ---- opening an existing vault ---- */
  $('b-open').onclick = async function () {
    try {
      const bytes = await S.open();
      LV.format.parseHeader(bytes);          // fail fast on the wrong file
      V.setPending(bytes);
      $('fname').textContent = S.fileName();
      ui.showStage('unlock');
      $('pp').focus();
    } catch (e) {
      if (e.name !== 'AbortError') ui.toast(e.message);
    }
  };

  $('b-unlock').onclick = async function () {
    const m = $('m-unlock');
    const entered = $('pp').value.trim();
    if (!entered) { m.textContent = 'Enter your passphrase.'; return; }

    m.textContent = '';
    $('b-unlock').textContent = 'Deriving key…';
    await new Promise(function (r) { setTimeout(r, 20); });   // let the label paint

    try {
      const t0 = performance.now();
      const result = await C.decryptVault(V.getPending(), entered);
      console.log('unlock took', Math.round(performance.now() - t0), 'ms');
      V.adopt(result.data, entered);
      $('pp').value = '';
      enterVault();
    } catch (e) {
      m.textContent = e.message;
    } finally {
      $('b-unlock').textContent = 'Unlock';
    }
  };

  /* ---- creating a new vault ---- */
  $('b-new').onclick = function () {
    candidate = G.passphrase();
    ui.renderPhrase(candidate);
    $('confirm').value = '';
    ui.showStage('new');
  };

  $('b-regen').onclick = function () {
    candidate = G.passphrase();
    ui.renderPhrase(candidate);
    $('confirm').value = '';
  };

  $('b-copyphrase').onclick = async function () {
    try {
      await navigator.clipboard.writeText(candidate.join(' '));
      ui.toast('Passphrase copied. Paste it somewhere safe now.');
    } catch (e) {
      ui.toast('Clipboard blocked by the browser');
    }
  };

  $('b-create').onclick = async function () {
    const m = $('m-new');
    if (C.canonical($('confirm').value) !== C.canonical(candidate.join(' '))) {
      m.textContent = 'That does not match. Check the spacing and spelling.';
      return;
    }
    m.textContent = '';
    $('b-create').textContent = 'Encrypting…';
    await new Promise(function (r) { setTimeout(r, 20); });

    try {
      V.create(candidate);
      S.reset('my.vault');
      const bytes = await C.encryptVault(V.get(), V.getPhrase());
      ui.toast(await S.save(bytes));
      enterVault();
    } catch (e) {
      m.textContent = e.message;
    } finally {
      $('b-create').textContent = 'Create vault';
    }
  };

  /* ---- entries ---- */
  $('b-add').onclick = function () { openEntrySheet(null); };
  $('b-cancel').onclick = closeEntrySheet;
  $('b-genpw').onclick = function () { $('e-secret').value = G.password(20); };

  $('b-save-entry').onclick = function () {
    const title = $('e-title').value.trim();
    if (!title) { $('e-title').focus(); ui.toast('Give the entry a name'); return; }

    const fields = {
      title: title,
      username: $('e-user').value.trim(),
      secret: $('e-secret').value,
      url: $('e-url').value.trim()
    };

    const wasEdit = editingId !== null;
    if (wasEdit) {
      // The vault can lock while the sheet is open, which drops the
      // model. An id that no longer resolves means the edit is stale.
      if (!V.isOpen() || !V.updateEntry(editingId, fields)) {
        closeEntrySheet();
        ui.toast('That entry is no longer there');
        return;
      }
    } else {
      V.addEntry(fields);
    }

    closeEntrySheet();
    refresh();
    ui.toast(wasEdit ? 'Updated. Save to keep the change.' : 'Added. Save to keep the change.');
  };

  /* ---- saving and locking ---- */
  $('b-save').onclick = async function () {
    $('b-save').textContent = 'Encrypting…';
    await new Promise(function (r) { setTimeout(r, 20); });
    try {
      V.bumpRevision();
      const bytes = await C.encryptVault(V.get(), V.getPhrase());
      ui.toast(await S.save(bytes));
    } catch (e) {
      ui.toast(e.message);
    } finally {
      $('b-save').textContent = 'Save vault';
      V.resetIdle();
    }
  };

  $('b-lock').onclick = function () { lock('Locked'); };
  $('b-back').onclick = function () { V.setPending(null); lock(); };
  $('b-back2').onclick = function () { candidate = []; lock(); };

  /* ---- idle handling ---- */
  V.onIdleLock(function () {
    editingId = null;
    ui.showSealed();
    ui.toast('Locked after 3 minutes idle');
  });
  ['pointerdown', 'keydown', 'visibilitychange'].forEach(function (ev) {
    document.addEventListener(ev, V.resetIdle, { passive: true });
  });

  /* ---- boot ---- */
  ui.setBuildInfo(C.HAS_ARGON2);
  lock();
})();
