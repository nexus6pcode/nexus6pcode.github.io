// Loads the site's three encrypted files once the Flutter app passes in the
// password: lottery_lib.json (the lottery_lib WebAssembly, from
// pack_lottery_lib), and the two lottery_file_creator makes after every
// drawing: lottery_numbers.json (Ohio Lottery's yearly CSV exports) and
// lottery_bell_curves.json (the bell curves as of those numbers). All are
// PBKDF2 + AES-GCM. The wasm functions are then on window.lotteryWasm with
// the numbers and bell curves loaded.
(function () {
  const fromBase64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  let libFile = null;
  let numbersFile = null;
  let bellCurvesFile = null;

  async function fetchFile(url) {
    const response = await fetch(url, { cache: 'no-store' });
    if (!response.ok) throw new Error(`Could not load ${url}: ${response.status}`);
    try {
      return JSON.parse(await response.text());
    } catch (e) {
      // Servers that fall back to index.html for missing files end up here.
      throw new Error(`${url} is missing or isn't one of the lottery site's files. It belongs next to index.html.`);
    }
  }

  async function inflate(bytes) {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  async function decrypt(password, file) {
    const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: fromBase64(file.salt), iterations: 600000 }, baseKey, 256);
    const key = await crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['decrypt']);
    const data = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(file.iv), additionalData: fromBase64(file.aad) }, key, fromBase64(file.data));
    return inflate(new Uint8Array(data));
  }

  globalThis.lotteryLoader = {
    // Fetches the files and returns when the numbers were last updated.
    async built(libUrl, numbersUrl, bellCurvesUrl) {
      [libFile, numbersFile, bellCurvesFile] = await Promise.all([fetchFile(libUrl), fetchFile(numbersUrl), fetchFile(bellCurvesUrl)]);
      return numbersFile.built;
    },

    // Decrypts the files, starts the wasm and loads the numbers and bell
    // curves into it. Returns JSON with lines saying when each file was built.
    async load(password) {
      let lib, numbers, bellCurves;
      try {
        [lib, numbers, bellCurves] = await Promise.all([decrypt(password, libFile), decrypt(password, numbersFile), decrypt(password, bellCurvesFile)]);
      } catch (e) {
        throw new Error('Wrong password.');
      }
      // lottery_lib.json holds [4-byte header length][header JSON][wasm].
      const headerLength = new DataView(lib.buffer, lib.byteOffset, 4).getUint32(0);
      const header = JSON.parse(new TextDecoder().decode(lib.subarray(4, 4 + headerLength)));
      const wasmBytes = lib.subarray(4 + headerLength);

      const wasmBindgen = new Function(`${header.wasm_js}\nreturn wasm_bindgen;`)();
      await wasmBindgen({ module_or_path: wasmBytes });
      wasmBindgen.init_panic_hook();
      wasmBindgen.load_csv_wasm(new TextDecoder().decode(numbers));
      wasmBindgen.load_bell_curves_wasm(new TextDecoder().decode(bellCurves));
      globalThis.lotteryWasm = wasmBindgen;

      return JSON.stringify({
        time_stamp: [`numbers updated:${numbersFile.built}`, `bell curves made:${bellCurvesFile.built}`, `lottery_lib built:${libFile.built}`],
      });
    },
  };
})();
