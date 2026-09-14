/* storage.js — reading and writing the vault file.
 *
 * Where the File System Access API exists (Chromium desktop, and
 * Chrome on Android since v132) a file handle is kept so saves go
 * back to the same file. Firefox and Safari have declined to
 * implement it, so those fall back to picker-in / download-out.
 */
window.LV = window.LV || {};

LV.storage = (function () {
  const ACCEPT = { description: 'Vault file', accept: { 'application/octet-stream': ['.vault'] } };

  const canPick = 'showOpenFilePicker' in window && (function () {
    try { return window.self === window.top; } catch (e) { return false; }
  })();

  let handle = null;
  let name = 'my.vault';

  function fileName() { return name; }
  function inPlace() { return handle !== null; }

  function reset(newName) {
    handle = null;
    name = newName || 'my.vault';
  }

  async function open() {
    if (canPick) {
      const [h] = await window.showOpenFilePicker({ types: [ACCEPT] });
      handle = h;
      name = h.name;
      return new Uint8Array(await (await h.getFile()).arrayBuffer());
    }
    return new Promise(function (resolve, reject) {
      const inp = document.createElement('input');
      inp.type = 'file';
      inp.accept = '.vault,application/octet-stream';
      inp.onchange = async function () {
        const f = inp.files[0];
        if (!f) return reject(new Error('No file chosen'));
        name = f.name;
        handle = null;
        resolve(new Uint8Array(await f.arrayBuffer()));
      };
      inp.click();
    });
  }

  async function save(bytes) {
    const blob = new Blob([bytes], { type: 'application/octet-stream' });

    if (handle) {
      const w = await handle.createWritable();
      await w.write(blob);
      await w.close();
      return 'Saved to ' + name;
    }

    if (canPick) {
      try {
        handle = await window.showSaveFilePicker({ suggestedName: name, types: [ACCEPT] });
        name = handle.name;
        const w = await handle.createWritable();
        await w.write(blob);
        await w.close();
        return 'Saved to ' + name;
      } catch (e) {
        if (e.name === 'AbortError') return 'Save cancelled';
      }
    }

    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 4000);
    return 'Downloaded ' + name;
  }

  return { canPick, open, save, reset, fileName, inPlace };
})();
