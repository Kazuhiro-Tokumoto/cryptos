import { dirname, join } from "path";
import { fileURLToPath } from "url";

// Node かどうか判定（window が無ければ Node 扱い）
const IS_NODE = typeof window === "undefined";
const __dirname = IS_NODE ? dirname(fileURLToPath(import.meta.url)) : null;

// ---- wasm バイナリ取得（Node: fs / Web: fetch）----
async function loadWasmBytes() {
  if (IS_NODE) {
    const { readFileSync } = await import("fs");
    return readFileSync(join(__dirname, "ecdsa_wasm.wasm"));
  }

  const wasmUrl = new URL("./ecdsa_wasm.wasm", import.meta.url);
  const res = await fetch(wasmUrl);
  if (!res.ok) {
    throw new Error(`Failed to fetch wasm: ${res.status} ${res.statusText}`);
  }
  return new Uint8Array(await res.arrayBuffer());
}

// ---- Emscripten 最低限 import（resize_heap）----
function makeImports() {
  const imports = { a: { a: () => 0 } };

  // memory.grow を提供（ブラウザでも動く��
  const memory = new WebAssembly.Memory({ initial: 256, maximum: 32768 });
  const resizeHeap = (size) => {
    const delta = size - memory.buffer.byteLength;
    if (delta <= 0) return 1;
    const pages = Math.ceil(delta / 65536);
    try {
      memory.grow(pages);
      return 1;
    } catch {
      return 0;
    }
  };
  imports.a.a = resizeHeap;

  return { imports, memory };
}

async function instantiate() {
  const wasmBytes = await loadWasmBytes();
  const { imports } = makeImports();

  // bytes が Buffer(Uint8Array) でも OK
  const { instance } = await WebAssembly.instantiate(wasmBytes, imports);
  return instance.exports;
}

const exp = await instantiate();

// main.c の assignWasmExports コメントに合わせた対応
const wasm = {
  memory: exp.b,
  ec_get_buf: exp.d,
  ec_buf_size: exp.e,
  ec_init: exp.f,
  ec_generate_keypair: exp.g,
  ec_privkey_to_pubkey: exp.h,
  ec_sign: exp.i,
  malloc: exp.j,
  free: exp.k,
  ec_verify: exp.l,
};

// スタック操作（emscripten）
const stackRestore = exp.m; // __emscripten_stack_restore
const stackAlloc = exp.n; // __emscripten_stack_alloc
const stackSave = exp.o; // emscripten_stack_get_current

// 初期化
wasm.ec_init();

// HEAP view（grow後もバッファ参照は取り直す）
const heapU8 = () => new Uint8Array(wasm.memory.buffer);

function withStack(fn) {
  const sp = stackSave();
  try {
    return fn();
  } finally {
    stackRestore(sp);
  }
}

function writeArrayIntoStack(arr) {
  const ptr = stackAlloc(arr.length);
  heapU8().set(arr, ptr);
  return ptr;
}

export class PointPairSchnorrP256Wasm {
  constructor() {
    // すでに top-level await で instantiate 済み
    this.ready = Promise.resolve();
  }

  generateKeyPair() {
    const N =
      0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

    let rand32;
    do {
      rand32 = new Uint8Array(32);
      crypto.getRandomValues(rand32);
    } while (this._b2i(rand32) >= N || this._b2i(rand32) === 0n);

    return withStack(() => {
      const privPtr = writeArrayIntoStack(rand32);
      wasm.ec_generate_keypair(privPtr);

      const bufPtr = wasm.ec_get_buf();
      const h = heapU8();
      return {
        privateKey: h.slice(bufPtr, bufPtr + 32),
        publicKey: [
          h.slice(bufPtr + 32, bufPtr + 64),
          h.slice(bufPtr + 64, bufPtr + 96),
        ],
      };
    });
  }

  // 署名: Rx(32) + Ry(32) + s(32) = 96B
  sign(message, privKey) {
    return withStack(() => {
      const mPtr = writeArrayIntoStack(message);
      const pPtr = writeArrayIntoStack(privKey);

      wasm.ec_sign(mPtr, message.length, pPtr);

      const bufPtr = wasm.ec_get_buf();
      const h = heapU8();
      return [
        h.slice(bufPtr, bufPtr + 32),
        h.slice(bufPtr + 32, bufPtr + 64),
        h.slice(bufPtr + 64, bufPtr + 96),
      ];
    });
  }

  verify(message, pubKey, signature) {
    const pub = new Uint8Array(64);
    pub.set(pubKey[0], 0);
    pub.set(pubKey[1], 32);

    const sig = new Uint8Array(96);
    sig.set(signature[0], 0);
    sig.set(signature[1], 32);
    sig.set(signature[2], 64);

    return withStack(() => {
      const mPtr = writeArrayIntoStack(message);
      const pubPtr = writeArrayIntoStack(pub);
      const sigPtr = writeArrayIntoStack(sig);

      const result = wasm.ec_verify(mPtr, message.length, pubPtr, sigPtr);
      return result === 1;
    });
  }

  privatekeytoPublicKey(privKey) {
    return withStack(() => {
      const ptr = writeArrayIntoStack(privKey);
      wasm.ec_privkey_to_pubkey(ptr);

      const bufPtr = wasm.ec_get_buf();
      const h = heapU8();
      return [h.slice(bufPtr, bufPtr + 32), h.slice(bufPtr + 32, bufPtr + 64)];
    });
  }

  _b2i(bytes) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
    let r = 0n;
    let i = 0;
    for (; i <= bytes.length - 8; i += 8) r = (r << 64n) + view.getBigUint64(i);
    for (; i < bytes.length; i++) r = (r << 8n) + BigInt(bytes[i]);
    return r;
  }
}