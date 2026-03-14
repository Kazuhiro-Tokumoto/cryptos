import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ecdsa_wasm.js を経由せず wasm バイナリを直接ロード
// assignWasmExports と同じマッピングをここで再現する
const wasmBuf  = readFileSync(join(__dirname, "ecdsa_wasm.wasm"));
const imports  = { a: { a: () => {} } }; // _emscripten_resize_heap ダミー

// メモリ確保用: grow が必要なので本物を渡す
const memory   = new WebAssembly.Memory({ initial: 256, maximum: 32768 });
const resizeHeap = (size) => {
  const pages = Math.ceil((size - memory.buffer.byteLength) / 65536);
  if (pages > 0) try { memory.grow(pages); } catch(e) { return 0; }
  return 1;
};
imports.a.a = resizeHeap;

const { instance } = await WebAssembly.instantiate(wasmBuf, imports);
const exp = instance.exports;

// assignWasmExports と同じ順序で関数を取り出す
// ecdsa_wasm.js より:
//   d=ec_get_buf, e=ec_buf_size, f=ec_init, g=ec_generate_keypair,
//   h=ec_privkey_to_pubkey, i=ec_sign, j=malloc, k=free, l=ec_verify
//   b=memory
const wasm = {
  memory:              exp.b,
  ec_get_buf:          exp.d,
  ec_buf_size:         exp.e,
  ec_init:             exp.f,
  ec_generate_keypair: exp.g,
  ec_privkey_to_pubkey:exp.h,
  ec_sign:             exp.i,
  malloc:              exp.j,
  free:                exp.k,
  ec_verify:           exp.l,
};

// スタック操作
const stackSave    = exp.o; // emscripten_stack_get_current
const stackAlloc   = exp.n; // __emscripten_stack_alloc
const stackRestore = exp.m; // __emscripten_stack_restore

// 初期化
wasm.ec_init();

// HEAP ビュー（grow 後も再取得が必要）
const heap = () => new Uint8Array(wasm.memory.buffer);

// ccall array: スタックに書き込んでポインタを返す
function writeArray(arr) {
  const stack = stackSave();
  const ptr   = stackAlloc(arr.length);
  new Uint8Array(wasm.memory.buffer).set(arr, ptr);
  return { ptr, stack };
}

export class PointPairSchnorrP256Wasm {
  constructor() {
    this.ready = Promise.resolve();
  }

  generateKeyPair() {
    const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    let rand32;
    do {
      rand32 = new Uint8Array(32);
      crypto.getRandomValues(rand32);
    } while (this._b2i(rand32) >= N || this._b2i(rand32) === 0n);

    const { ptr, stack } = writeArray(rand32);
    wasm.ec_generate_keypair(ptr);
    stackRestore(stack);

    const bufPtr = wasm.ec_get_buf();
    const h = heap();
    return {
      privateKey: h.slice(bufPtr,      bufPtr + 32),
      publicKey: [h.slice(bufPtr + 32, bufPtr + 64),
                  h.slice(bufPtr + 64, bufPtr + 96)]
    };
  }

  sign(message, privKey) {
    const { ptr: mPtr, stack: s1 } = writeArray(message);
    const { ptr: pPtr, stack: s2 } = writeArray(privKey);
    wasm.ec_sign(mPtr, message.length, pPtr);
    stackRestore(s1);

    const bufPtr = wasm.ec_get_buf();
    const h = heap();
    return [h.slice(bufPtr,      bufPtr + 32),
            h.slice(bufPtr + 32, bufPtr + 64),
            h.slice(bufPtr + 64, bufPtr + 96)];
  }

  verify(message, pubKey, signature) {
    const pub = new Uint8Array(64);
    pub.set(pubKey[0],  0);
    pub.set(pubKey[1], 32);

    const sig = new Uint8Array(96);
    sig.set(signature[0],  0);
    sig.set(signature[1], 32);
    sig.set(signature[2], 64);

    const { ptr: mPtr, stack } = writeArray(message);
    const { ptr: pubPtr }      = writeArray(pub);
    const { ptr: sigPtr }      = writeArray(sig);
    const result = wasm.ec_verify(mPtr, message.length, pubPtr, sigPtr);
    stackRestore(stack);

    return result === 1;
  }

  privatekeytoPublicKey(privKey) {
    const { ptr, stack } = writeArray(privKey);
    wasm.ec_privkey_to_pubkey(ptr);
    stackRestore(stack);

    const bufPtr = wasm.ec_get_buf();
    const h = heap();
    return [h.slice(bufPtr,      bufPtr + 32),
            h.slice(bufPtr + 32, bufPtr + 64)];
  }

  _b2i(bytes) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
    let r = 0n;
    for (let i = 0; i <= bytes.length - 8; i += 8)
      r = (r << 64n) + view.getBigUint64(i);
    for (let i = bytes.length - (bytes.length % 8); i < bytes.length; i++)
      r = (r << 8n) + BigInt(bytes[i]);
    return r;
  }
}
