import { createRequire } from "module";
const require = createRequire(import.meta.url);
const _mod = require("./ecdsa_wasm.js");
const ec = await (typeof _mod === "function" ? _mod() : Promise.resolve(_mod));
console.log("type of ec:", typeof ec);
console.log("keys with _ec:", Object.keys(ec).filter(k => k.startsWith("_ec")));
