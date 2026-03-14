import { PointPairSchnorrP256Wasm } from "./ecdsa_wasm_wrapper.mjs";

const dsa = new PointPairSchnorrP256Wasm();
await dsa.ready; // WASMロード完了を待つ

const encoder = new TextEncoder();
const message = encoder.encode("Hello, ECDSA!");

const { privateKey, publicKey } = dsa.generateKeyPair();
const sig = dsa.sign(message, privateKey);
console.log     ("Signature:", sig);
const ok  = dsa.verify(message, publicKey, sig);
console.log("Verification:", ok); // true