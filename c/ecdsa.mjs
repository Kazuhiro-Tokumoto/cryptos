import { PointPairSchnorrP256Wasm } from "./ecdsa_wasm_wrapper.mjs";

const dsa = new PointPairSchnorrP256Wasm();
await dsa.ready;

const msg = new TextEncoder().encode("Hello, ECDSA!");
const { privateKey, publicKey } = dsa.generateKeyPair();
const sig = dsa.sign(msg, privateKey);

console.log("pub len", publicKey.length, publicKey[0].length, publicKey[1].length);
console.log("sig len", sig.length, sig.map((x) => x.length));

console.log("ok", dsa.verify(msg, publicKey, sig));