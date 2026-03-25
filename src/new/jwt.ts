type JSONValue =
  | string
  | number
  | boolean
  | null
  | { [key: string]: JSONValue }
  | JSONValue[];

export class myjwt {
  public sha256(data: Uint8Array): Uint8Array {
    const K = new Uint32Array([
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]);

    const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));

    let h0 = 0x6a09e667,
      h1 = 0xbb67ae85,
      h2 = 0x3c6ef372,
      h3 = 0xa54ff53a;
    let h4 = 0x510e527f,
      h5 = 0x9b05688c,
      h6 = 0x1f83d9ab,
      h7 = 0x5be0cd19;

    const len = data.length;
    const bitLen = len * 8;
    const blockCount = Math.ceil((len + 9) / 64);
    const blocks = new Uint8Array(blockCount * 64);
    blocks.set(data);
    blocks[len] = 0x80;
    const view = new DataView(blocks.buffer);
    view.setUint32(blocks.length - 8, Math.floor(bitLen / 0x100000000), false);
    view.setUint32(blocks.length - 4, bitLen >>> 0, false);

    for (let i = 0; i < blocks.length; i += 64) {
      const W = new Uint32Array(64);
      for (let t = 0; t < 16; t++) {
        W[t] = view.getUint32(i + t * 4, false);
      }
      for (let t = 16; t < 64; t++) {
        const s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
        const s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
        W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
      }

      let a = h0,
        b = h1,
        c = h2,
        d = h3;
      let e = h4,
        f = h5,
        g = h6,
        h = h7;

      for (let t = 0; t < 64; t++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ ((~e >>> 0) & g); // ✅ ~e を明示的にuint32化
        const temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;

        h = g;
        g = f;
        f = e;
        e = (d + temp1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) >>> 0;
      }

      h0 = (h0 + a) >>> 0;
      h1 = (h1 + b) >>> 0;
      h2 = (h2 + c) >>> 0;
      h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0;
      h5 = (h5 + f) >>> 0;
      h6 = (h6 + g) >>> 0;
      h7 = (h7 + h) >>> 0;
    }

    const result = new Uint8Array(32);
    const rv = new DataView(result.buffer);
    rv.setUint32(0, h0, false);
    rv.setUint32(4, h1, false);
    rv.setUint32(8, h2, false);
    rv.setUint32(12, h3, false);
    rv.setUint32(16, h4, false);
    rv.setUint32(20, h5, false);
    rv.setUint32(24, h6, false);
    rv.setUint32(28, h7, false);
    return result;
  }
  private readonly schnorr: PointPairSchnorrP256;
  private readonly ecdsa: p_256;
  private readonly hmac;
  constructor() {
    this.schnorr = new PointPairSchnorrP256();
    this.hmac = this.hmacSha256.bind(this);
    this.ecdsa = new p_256();
  }

  // ---------------------------------------------------------------------
  // ユーティリティ
  // ---------------------------------------------------------------------
  private bigintToHex(n: bigint, byteLength?: number): string {
    const hex = n.toString(16).toUpperCase();
    const padLen = byteLength ? byteLength * 2 : hex.length + (hex.length % 2);
    return hex.padStart(padLen, "0");
  }
  private BigintToBytes(n: bigint, byteLength?: number): Uint8Array {
    const hex = this.bigintToHex(n, byteLength);
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
  private hexToBigInt(hex: string): bigint {
    return BigInt("0x" + hex);
  }
  private bytesToBigInt(bytes: Uint8Array): bigint {
    const len = bytes.length;
    let res = 0n;
    const view = new DataView(bytes.buffer, bytes.byteOffset, len);

    let i = 0;
    for (; i <= len - 8; i += 8) {
      res = (res << 64n) + view.getBigUint64(i);
    }
    for (; i < len; i++) {
      res = (res << 8n) + BigInt(bytes[i]);
    }
    return res;
  }
  public bytesToHex(bytes: Uint8Array): string {
    return this.bigintToHex(this.bytesToBigInt(bytes));
  }
  public hexToBytes(hex: string): Uint8Array {
    return this.BigintToBytes(this.hexToBigInt(hex));
  }
  private concat(...arrays: Uint8Array[]): Uint8Array {
    const total = arrays.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) {
      out.set(a, offset);
      offset += a.length;
    }
    return out;
  }

  // ---------------------------------------------------------------------
  //HMAC-SHA256
  // ---------------------------------------------------------------------
  private hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
    const BLOCK = 64;
    const k = key.length > BLOCK ? this.sha256(key) : key;
    const kPadded = new Uint8Array(BLOCK);
    kPadded.set(k);
    const ipad = kPadded.map((b) => b ^ 0x36);
    const opad = kPadded.map((b) => b ^ 0x5c);
    return this.sha256(this.concat(opad, this.sha256(this.concat(ipad, data))));
  }

  // ---------------------------------------------------------------------
  // 独自バイナリソートアルゴリズム
  // ---------------------------------------------------------------------
  private Sort(input: ArrayBufferView | ArrayBuffer): Uint8Array {
    const data = ArrayBuffer.isView(input)
      ? new Uint8Array(input.buffer, input.byteOffset, input.byteLength)
      : new Uint8Array(input);

    const len = data.length;
    const counts = new Uint32Array(256);
    let effectiveLen = 0;

    // --- STAGE 1: 0x20以下のノイズをスキップしてカウント ---
    for (let i = 0; i < len; i++) {
      const b = data[i];

      // 0x20 (Space) 以下の制御文字 + スペースをすべて除外
      if (b <= 0x20) {
        continue;
      }

      counts[b]++;
      effectiveLen++;
    }

    // --- STAGE 2: 0x21 (!) から上の文字で構築 ---
    const result = new Uint8Array(effectiveLen);
    let offset = 0;
    for (let val = 0x21; val < 256; val++) {
      const count = counts[val];
      if (count > 0) {
        result.fill(val, offset, offset + count);
        offset += count;
      }
    }

    return result;
  }

  // ---------------------------------------------------------------------
  //JSONバイナリ化からのソート
  // ---------------------------------------------------------------------

  private jsonsort(input: JSONValue): Uint8Array {
    const inputStr = JSON.stringify(input);
    const inputBytes = new TextEncoder().encode(inputStr);
    return this.Sort(inputBytes);
  }

  //----------------------------------------------------------------------
  //JWTパーサー
  //----------------------------------------------------------------------
  public parseJWT(token: string): {
    header: JSONValue;
    payload: JSONValue;
    signature: Uint8Array;
  } {
    const parts = token.split(".");
    if (parts.length !== 3) throw new Error("Invalid JWT format");

    const decode = (b64url: string): Uint8Array => {
      let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
      while (b64.length % 4 !== 0) b64 += "=";
      const bin =
        typeof atob === "function"
          ? atob(b64)
          : Buffer.from(b64, "base64").toString("binary");
      return Uint8Array.from(bin, (c) => c.charCodeAt(0));
    };

    const decoder = new TextDecoder();
    const header = JSON.parse(decoder.decode(decode(parts[0]))) as JSONValue;
    const payload = JSON.parse(decoder.decode(decode(parts[1]))) as JSONValue;
    const signature = decode(parts[2]);

    return { header, payload, signature };
  }

  //----------------------------------------------------------------------
  //JWT作成
  //----------------------------------------------------------------------
  private makeJWT(
    header: JSONValue,
    payload: JSONValue,
    signature: Uint8Array,
  ): string {
    const encode = (data: any): string => {
      // 1. ソートせず、そのままの順序で文字列化
      const jsonStr = typeof data === "string" ? data : JSON.stringify(data);
      const bytes = new TextEncoder().encode(jsonStr);

      // 2. Base64URL エンコード（パディング除去あり）
      const bin = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
      return btoa(bin)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    };

    const encodeSig = (bytes: Uint8Array): string => {
      // 署名（バイナリ）も同様に Base64URL 化
      const bin = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
      return btoa(bin)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    };

    const headerB64 = encode(header);
    const payloadB64 = encode(payload);
    const signatureB64 = encodeSig(signature);

    return `${headerB64}.${payloadB64}.${signatureB64}`;
  }

  private signschnorr(
    header: JSONValue,
    payload: JSONValue,
    privKey: Uint8Array,
  ): [Uint8Array, Uint8Array, Uint8Array] {
    const headersorted = this.jsonsort(header);
    const payloadsorted = this.jsonsort(payload);
    const contacted = this.concat(headersorted, payloadsorted);
    const sorted = this.Sort(contacted);
    const signeture = this.schnorr.sign(sorted, privKey);
    return signeture;
  }

  private signecdsa(
    header: JSONValue,
    payload: JSONValue,
    privKey: Uint8Array,
  ): [Uint8Array, Uint8Array] {
    const headersorted = this.jsonsort(header);
    const payloadsorted = this.jsonsort(payload);
    const contacted = this.concat(headersorted, payloadsorted);
    const sorted = this.Sort(contacted);
    const signeture = this.ecdsa.sign(sorted, privKey);
    return signeture;
  }

  private signHMAC(
    header: JSONValue,
    payload: JSONValue,
    secret: Uint8Array,
  ): Uint8Array {
    const headersorted = this.jsonsort(header);
    const payloadsorted = this.jsonsort(payload);
    const contacted = this.concat(headersorted, payloadsorted);
    const sorted = this.Sort(contacted);
    const signeture = this.hmac(secret, sorted);
    return signeture;
  }

  private selectAlgAndSign(
    alg: string,
    payload: JSONValue,
    key: Uint8Array,
  ): { token: string; publickey?: [Uint8Array, Uint8Array] } {
    const header: JSONValue = { alg: alg, typ: "DLYAJWT" };
    switch (alg) {
      case "SchnorrP256":
        const sig = this.signschnorr(header, payload, key);
        return {
          token: this.makeJWT(
            header,
            payload,
            this.concat(sig[0], sig[1], sig[2]),
          ),
          publickey: this.schnorr.privatekeytoPublicKey(key), // Assuming there's a method to extract the public key from the private key
        };
      case "ECDSA_P256":
        const sig2 = this.signecdsa(header, payload, key);
        return {
          token: this.makeJWT(header, payload, this.concat(sig2[0], sig2[1])),
          publickey: this.ecdsa.privateKeyToPublicKey(key), // Assuming there's a method to extract the public key from the private key
        };
      case "HMAC_SHA256":
        const sig3 = this.signHMAC(header, payload, key);
        return {
          token: this.makeJWT(header, payload, sig3),
        };
      default:
        throw new Error(`Unsupported algorithm: ${alg}`);
    }
  }

  public createJWT(
    alg: string,
    payload: JSONValue,
    key: Uint8Array,
  ): { token: string; publickey?: [Uint8Array, Uint8Array] } {
    return { ...this.selectAlgAndSign(alg, payload, key) };
  }

  // ----------------------------------------------------------------------
  // JWT検証
  // ----------------------------------------------------------------------
  private verifySchnorr(
    header: JSONValue,
    payload: JSONValue,
    signature: [Uint8Array, Uint8Array, Uint8Array],
    pubKey: [Uint8Array, Uint8Array],
  ): boolean {
    const headersorted = this.jsonsort(header);
    const payloadsorted = this.jsonsort(payload);
    const contacted = this.concat(headersorted, payloadsorted);
    const sorted = this.Sort(contacted);
    return this.schnorr.verify(sorted, pubKey, signature);
  }

  private verifyECDSA(
    header: JSONValue,
    payload: JSONValue,
    signature: [Uint8Array, Uint8Array],
    pubKey: [Uint8Array, Uint8Array],
  ): boolean {
    const headersorted = this.jsonsort(header);
    const payloadsorted = this.jsonsort(payload);
    const contacted = this.concat(headersorted, payloadsorted);
    const sorted = this.Sort(contacted);
    return this.ecdsa.verify(sorted, signature, pubKey);
  }

  private verifyHMAC(
    header: JSONValue,
    payload: JSONValue,
    signature: Uint8Array,
    secret: Uint8Array,
  ): boolean {
    const headersorted = this.jsonsort(header);
    const payloadsorted = this.jsonsort(payload);
    const contacted = this.concat(headersorted, payloadsorted);
    const sorted = this.Sort(contacted);
    const expectedSig = this.hmac(secret, sorted);
    return (
      expectedSig.length === signature.length &&
      expectedSig.every((b, i) => b === signature[i])
    );
  }

  private selectAlgAndVerify(
    heder: JSONValue,
    payload: JSONValue,
    signature: Uint8Array,
    key: Uint8Array | [Uint8Array, Uint8Array],
  ): boolean {
    if (typeof heder !== "object" || heder === null || !("alg" in heder)) {
      throw new Error("Invalid JWT header");
    }
    const alg = (heder as any).alg;
    switch (alg) {
      case "SchnorrP256":
        if (!Array.isArray(key) || key.length !== 2) {
          throw new Error("Invalid public key for SchnorrP256");
        }
        return this.verifySchnorr(
          heder,
          payload,
          [
            signature.subarray(0, 32),
            signature.subarray(32, 64),
            signature.subarray(64, 96),
          ],
          [key[0], key[1]],
        );
      case "ECDSA_P256":
        if (!Array.isArray(key) || key.length !== 2) {
          throw new Error("Invalid public key for ECDSA_P256");
        }
        return this.verifyECDSA(
          heder,
          payload,
          [signature.subarray(0, 32), signature.subarray(32, 64)],
          [key[0], key[1]],
        );
      case "HMAC_SHA256":
        if (key instanceof Uint8Array) {
          return this.verifyHMAC(heder, payload, signature, key);
        } else {
          throw new Error("Invalid key for HMAC_SHA256");
        }
      default:
        throw new Error(`Unsupported algorithm: ${alg}`);
    }
  }

  public verifyJWT(
    token: string,
    key: Uint8Array | [Uint8Array, Uint8Array],
  ): boolean {
    const { header, payload, signature } = this.parseJWT(token);
    return this.selectAlgAndVerify(header, payload, signature, key);
  }
}
//---------------------------------------------------------------------
// 内部用class
// ---------------------------------------------------------------------
class PointPairSchnorrP256 {
  private readonly P =
    0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
  private readonly N =
    0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  private readonly G: [bigint, bigint] = [
    0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
  ];

  private readonly SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  private readonly _W = new Uint32Array(64);

  // ─── mod P 正規化 (常に [0, P) を返す) ───────────────────────────
  private m(x: bigint): bigint {
    const r = x % this.P;
    return r < 0n ? r + this.P : r;
  }

  private readonly G_precomp_window: [bigint, bigint, bigint][][] = (() => {
    const table: [bigint, bigint, bigint][][] = [];
    let base: [bigint, bigint, bigint] = [this.G[0], this.G[1], 1n];
    for (let i = 0; i < 32; i++) {
      const row: [bigint, bigint, bigint][] = new Array(256);
      row[0] = [0n, 1n, 0n];
      row[1] = base;
      for (let j = 2; j < 256; j++) row[j] = this.addJJ(row[j - 1], base);
      table.push(row);
      for (let j = 0; j < 8; j++) base = this.dblJ(base);
    }
    return table;
  })();

  // ─── Mixed add: P1 Jacobian, Q affine (Z=1) ──────────────────────
  private addMJ(
    P1: [bigint, bigint, bigint],
    X2: bigint,
    Y2: bigint,
  ): [bigint, bigint, bigint] {
    const [X1, Y1, Z1] = P1;
    if (Z1 === 0n) return [X2, Y2, 1n];
    const p = this.P;
    const Z1Z1 = (Z1 * Z1) % p;
    const U2 = (X2 * Z1Z1) % p;
    const S2 = (Y2 * ((Z1Z1 * Z1) % p)) % p;
    const H = this.m(U2 - X1);
    const RR = this.m(S2 - Y1);
    if (H === 0n) {
      if (RR === 0n) return this.dblJ(P1);
      return [0n, 1n, 0n];
    }
    const HH = (H * H) % p;
    const HHH = (HH * H) % p;
    const U1HH = (X1 * HH) % p;
    const X3 = this.m(RR * RR - HHH - 2n * U1HH);
    const Y3 = this.m(RR * this.m(U1HH - X3) - Y1 * HHH);
    const Z3 = (H * Z1) % p;
    return [X3, Y3, Z3];
  }

  // ─── Full Jacobian + Jacobian ─────────────────────────────────────
  private addJJ(
    P1: [bigint, bigint, bigint],
    Q: [bigint, bigint, bigint],
  ): [bigint, bigint, bigint] {
    const [X1, Y1, Z1] = P1;
    const [X2, Y2, Z2] = Q;
    if (Z1 === 0n) return Q;
    if (Z2 === 0n) return P1;
    if (Z2 === 1n) return this.addMJ(P1, X2, Y2);
    if (Z1 === 1n) return this.addMJ(Q, X1, Y1);
    const p = this.P;
    const Z1Z1 = (Z1 * Z1) % p;
    const Z2Z2 = (Z2 * Z2) % p;
    const U1 = (X1 * Z2Z2) % p;
    const U2 = (X2 * Z1Z1) % p;
    const S1 = (Y1 * ((Z2Z2 * Z2) % p)) % p;
    const S2 = (Y2 * ((Z1Z1 * Z1) % p)) % p;
    const H = this.m(U2 - U1);
    const RR = this.m(S2 - S1);
    if (H === 0n) {
      if (RR === 0n) return this.dblJ(P1);
      return [0n, 1n, 0n];
    }
    const HH = (H * H) % p;
    const HHH = (HH * H) % p;
    const U1HH = (U1 * HH) % p;
    const X3 = this.m(RR * RR - HHH - 2n * U1HH);
    const Y3 = this.m(RR * this.m(U1HH - X3) - S1 * HHH);
    const Z3 = (((H * Z1) % p) * Z2) % p;
    return [X3, Y3, Z3];
  }

  // ─── Doubling: a = -3 specialization ──────────────────────────────
  private dblJ(Pt: [bigint, bigint, bigint]): [bigint, bigint, bigint] {
    const [X, Y, Z] = Pt;
    if (Z === 0n) return Pt;
    const p = this.P;
    const YY = (Y * Y) % p;
    const YYYY = (YY * YY) % p;
    const ZZ = (Z * Z) % p;
    const S = (4n * ((X * YY) % p)) % p;
    const M = (3n * (((X + ZZ) * this.m(X - ZZ)) % p)) % p;
    const X3 = this.m(M * M - 2n * S);
    const Y3 = this.m(M * this.m(S - X3) - 8n * YYYY);
    return [X3, Y3, (2n * ((Y * Z) % p)) % p];
  }

  private toAffine(Pt: [bigint, bigint, bigint]): [bigint, bigint] {
    if (Pt[2] === 0n) return [0n, 0n];
    const invZ = this.inv(Pt[2], this.P);
    const invZ2 = this.m(invZ * invZ);
    const invZ3 = this.m(invZ2 * invZ);
    return [this.m(Pt[0] * invZ2), this.m(Pt[1] * invZ3)];
  }

  // Pre-cached shift amounts for scalarMultGJac
  private readonly _shifts: bigint[] = (() => {
    const s: bigint[] = [];
    for (let i = 0; i < 256; i += 8) s.push(BigInt(i));
    return s;
  })();

  private scalarMultGJac(k: bigint): [bigint, bigint, bigint] {
    const win0 = Number(k & 0xffn);
    let R: [bigint, bigint, bigint] = [...this.G_precomp_window[0][win0]];
    const shifts = this._shifts;
    for (let i = 1; i < 32; i++) {
      const win = Number((k >> shifts[i]) & 0xffn);
      if (win !== 0) R = this.addJJ(R, this.G_precomp_window[i][win]);
    }
    return R;
  }
  private scalarMultG(k: bigint): [bigint, bigint] {
    return this.toAffine(this.scalarMultGJac(k));
  }

  private scalarMult(Pt: [bigint, bigint], k: bigint): [bigint, bigint] {
    if (k < 0n) {
      Pt = this.negate(Pt);
      k = -k;
    }
    let R: [bigint, bigint, bigint] = [0n, 1n, 0n];
    let addend: [bigint, bigint, bigint] = [Pt[0], Pt[1], 1n];
    while (k > 0n) {
      if (k & 1n) R = this.addJJ(R, addend);
      addend = this.dblJ(addend);
      k >>= 1n;
    }
    return this.toAffine(R);
  }

  // ─── Arbitrary-point wNAF w=5 scalar mult (Jacobian result) ──────
  private scalarMultWNAF5Jac(
    Pt: [bigint, bigint],
    k: bigint,
  ): [bigint, bigint, bigint] {
    if (k === 0n) return [0n, 1n, 0n];
    if (k < 0n) {
      Pt = this.negate(Pt);
      k = -k;
    }
    const p = this.P;
    // Precomp odd multiples: table[i] = (2i+1)*Pt, i=0..15
    const Px = Pt[0],
      Py = Pt[1];
    const table: [bigint, bigint, bigint][] = new Array(16);
    table[0] = [Px, Py, 1n];
    const P2 = this.dblJ(table[0]);
    for (let i = 1; i < 16; i++) table[i] = this.addJJ(table[i - 1], P2);

    // Compute wNAF-5 representation
    const naf: number[] = [];
    let kk = k;
    while (kk > 0n) {
      if (kk & 1n) {
        let digit = Number(kk & 0x1fn); // mod 32
        if (digit >= 16) digit -= 32;
        kk -= BigInt(digit);
        naf.push(digit);
      } else {
        naf.push(0);
      }
      kk >>= 1n;
    }

    // Process from MSB
    let R: [bigint, bigint, bigint] = [0n, 1n, 0n];
    for (let i = naf.length - 1; i >= 0; i--) {
      R = this.dblJ(R);
      const d = naf[i];
      if (d > 0) {
        R = this.addJJ(R, table[(d - 1) >> 1]);
      } else if (d < 0) {
        const [tx, ty, tz] = table[(-d - 1) >> 1];
        R = this.addJJ(R, [tx, (p - ty) % p, tz]);
      }
    }
    return R;
  }

  private negate(P: [bigint, bigint]): [bigint, bigint] {
    return [P[0], this.m(-P[1])];
  }

  private inv(a: bigint, m: bigint): bigint {
    a %= m;
    if (a < 0n) a += m;
    if (a === 0n) throw new Error("inv: a == 0");
    let t = 0n,
      newT = 1n,
      r = m,
      newR = a;
    while (newR !== 0n) {
      const q = r / newR;
      const t0 = t;
      t = newT;
      newT = t0 - q * newT;
      const r0 = r;
      r = newR;
      newR = r0 - q * newR;
    }
    if (r !== 1n) throw new Error("inv: not invertible");
    if (t < 0n) t += m;
    return t;
  }

  public isPointOnCurve(Pt: [bigint, bigint]): boolean {
    const [x, y] = Pt;
    if (x === 0n && y === 0n) return false;
    const p = this.P;
    const x2 = (x * x) % p;
    const rhs =
      (((x2 * x) % p) -
        ((3n * x) % p) +
        0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn +
        2n * p) %
      p;
    return (y * y) % p === rhs;
  }

  public sign(
    message: Uint8Array,
    privKey: Uint8Array,
    publicKey?: [Uint8Array, Uint8Array],
  ): [Uint8Array, Uint8Array, Uint8Array] {
    const messageBigint = this.bytesToBigInt(message);
    const privKeyBigint = this.bytesToBigInt(privKey);
    const pubKeyBigint: [bigint, bigint] = publicKey
      ? [this.bytesToBigInt(publicKey[0]), this.bytesToBigInt(publicKey[1])]
      : this.scalarMultG(privKeyBigint);
    const mB = this.BigintToBytes(messageBigint);
    const k = this.generateK(mB, this.BigintToBytes(privKeyBigint));
    const R = this.scalarMultG(k);
    const e =
      this.bytesToBigInt(
        this.sha256(
          this.concat(
            this.BigintToBytes(R[0]),
            this.BigintToBytes(R[1]),
            this.BigintToBytes(pubKeyBigint[0]),
            this.BigintToBytes(pubKeyBigint[1]),
            mB,
          ),
        ),
      ) % this.N;
    if (e === 0n) throw new Error("e==0, retry");
    const s = (k + privKeyBigint * e) % this.N;
    return [
      this.BigintToBytes(R[0]),
      this.BigintToBytes(R[1]),
      this.BigintToBytes(s),
    ];
  }

  public verify(
    message: Uint8Array,
    pubKey: [Uint8Array, Uint8Array],
    signature: [Uint8Array, Uint8Array, Uint8Array],
  ): boolean {
    const messageBigint = this.bytesToBigInt(message);
    const pubKeyBigint: [bigint, bigint] = [
      this.bytesToBigInt(pubKey[0]),
      this.bytesToBigInt(pubKey[1]),
    ];
    const R: [bigint, bigint] = [
      this.bytesToBigInt(signature[0]),
      this.bytesToBigInt(signature[1]),
    ];
    const e =
      this.bytesToBigInt(
        this.sha256(
          this.concat(
            this.BigintToBytes(R[0]),
            this.BigintToBytes(R[1]),
            this.BigintToBytes(pubKeyBigint[0]),
            this.BigintToBytes(pubKeyBigint[1]),
            this.BigintToBytes(messageBigint),
          ),
        ),
      ) % this.N;
    if (e === 0n) return false;
    const s = this.bytesToBigInt(signature[2]);
    if (s === 0n) return false;

    // sG via precomp table (no doublings!) + (-e)P via w=4 window
    const negE = this.N - e;
    const sGJ = this.scalarMultGJac(s);
    const negEP = this.scalarMultWNAF5Jac(pubKeyBigint, negE);
    const lhs = this.addJJ(sGJ, negEP);

    // Compare Jacobian lhs with affine R without inversion
    if (lhs[2] === 0n) return false;
    const Z2 = this.m(lhs[2] * lhs[2]);
    const Z3 = this.m(Z2 * lhs[2]);
    return (
      this.m(lhs[0]) === this.m(R[0] * Z2) &&
      this.m(lhs[1]) === this.m(R[1] * Z3)
    );
  }

  public generateKeyPair(): {
    privateKey: Uint8Array;
    publicKey: [Uint8Array, Uint8Array];
  } {
    const privKey = this.getRandomBigInt(this.N);
    const pubKey = this.scalarMultG(privKey);
    return {
      privateKey: this.BigintToBytes(privKey),
      publicKey: [this.BigintToBytes(pubKey[0]), this.BigintToBytes(pubKey[1])],
    };
  }

  public sha256(data: Uint8Array): Uint8Array {
    const K = this.SHA256_K;
    const W = this._W;
    const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));
    let h0 = 0x6a09e667,
      h1 = 0xbb67ae85,
      h2 = 0x3c6ef372,
      h3 = 0xa54ff53a;
    let h4 = 0x510e527f,
      h5 = 0x9b05688c,
      h6 = 0x1f83d9ab,
      h7 = 0x5be0cd19;
    const len = data.length,
      bitLen = len * 8;
    const blockCount = Math.ceil((len + 9) / 64);
    const blocks = new Uint8Array(blockCount * 64);
    blocks.set(data);
    blocks[len] = 0x80;
    const view = new DataView(blocks.buffer);
    view.setUint32(blocks.length - 8, Math.floor(bitLen / 0x100000000), false);
    view.setUint32(blocks.length - 4, bitLen >>> 0, false);
    for (let i = 0; i < blocks.length; i += 64) {
      for (let t = 0; t < 16; t++) W[t] = view.getUint32(i + t * 4, false);
      for (let t = 16; t < 64; t++) {
        const s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
        const s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
        W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
      }
      let a = h0,
        b = h1,
        c = h2,
        d = h3,
        e = h4,
        f = h5,
        g = h6,
        h = h7;
      for (let t = 0; t < 64; t++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ ((~e >>> 0) & g);
        const temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;
        h = g;
        g = f;
        f = e;
        e = (d + temp1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) >>> 0;
      }
      h0 = (h0 + a) >>> 0;
      h1 = (h1 + b) >>> 0;
      h2 = (h2 + c) >>> 0;
      h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0;
      h5 = (h5 + f) >>> 0;
      h6 = (h6 + g) >>> 0;
      h7 = (h7 + h) >>> 0;
    }
    const result = new Uint8Array(32);
    const rv = new DataView(result.buffer);
    rv.setUint32(0, h0, false);
    rv.setUint32(4, h1, false);
    rv.setUint32(8, h2, false);
    rv.setUint32(12, h3, false);
    rv.setUint32(16, h4, false);
    rv.setUint32(20, h5, false);
    rv.setUint32(24, h6, false);
    rv.setUint32(28, h7, false);
    return result;
  }

  private hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
    const BLOCK = 64;
    const k = key.length > BLOCK ? this.sha256(key) : key;
    const kp = new Uint8Array(BLOCK);
    kp.set(k);
    const ipad = new Uint8Array(BLOCK),
      opad = new Uint8Array(BLOCK);
    for (let i = 0; i < BLOCK; i++) {
      ipad[i] = kp[i] ^ 0x36;
      opad[i] = kp[i] ^ 0x5c;
    }
    return this.sha256(this.concat(opad, this.sha256(this.concat(ipad, data))));
  }

  private generateK(message: Uint8Array, privateKey: Uint8Array): bigint {
    const qLen = 32,
      h1 = this.sha256(message);
    let V = new Uint8Array(qLen).fill(0x01),
      K = new Uint8Array(qLen).fill(0x00);
    const b0 = new Uint8Array([0x00]),
      b1 = new Uint8Array([0x01]);
    K = this.hmacSha256(
      K,
      this.concat(V, b0, privateKey, h1),
    ) as Uint8Array<ArrayBuffer>;
    V = this.hmacSha256(K, V) as Uint8Array<ArrayBuffer>;
    K = this.hmacSha256(
      K,
      this.concat(V, b1, privateKey, h1),
    ) as Uint8Array<ArrayBuffer>;
    V = this.hmacSha256(K, V) as Uint8Array<ArrayBuffer>;
    while (true) {
      let T = new Uint8Array(0);
      while (T.length < qLen) {
        V = this.hmacSha256(K, V) as Uint8Array<ArrayBuffer>;
        const next = new Uint8Array(T.length + V.length);
        next.set(T);
        next.set(V, T.length);
        T = next;
      }
      const k = this.bytesToBigInt(T.subarray(0, qLen));
      if (k >= 1n && k < this.N) return k;
      K = this.hmacSha256(K, this.concat(V, b0)) as Uint8Array<ArrayBuffer>;
      V = this.hmacSha256(K, V) as Uint8Array<ArrayBuffer>;
    }
  }

  private concat(...arrays: Uint8Array[]): Uint8Array {
    let total = 0;
    for (const a of arrays) total += a.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrays) {
      out.set(a, off);
      off += a.length;
    }
    return out;
  }
  private BigintToBytes(n: bigint): Uint8Array {
    const b = new Uint8Array(32);
    for (let i = 31; i >= 0; i--) {
      b[i] = Number(n & 0xffn);
      n >>= 8n;
    }
    return b;
  }
  private bytesToBigInt(bytes: Uint8Array): bigint {
    const len = bytes.length,
      view = new DataView(bytes.buffer, bytes.byteOffset, len);
    let r = 0n,
      i = 0;
    for (; i <= len - 8; i += 8) r = (r << 64n) + view.getBigUint64(i);
    for (; i < len; i++) r = (r << 8n) + BigInt(bytes[i]);
    return r;
  }
  public bytesToHex(bytes: Uint8Array): string {
    let hex = "";
    for (const b of bytes) hex += b.toString(16).toUpperCase().padStart(2, "0");
    return hex;
  }
  public hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++)
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return bytes;
  }
  private getRandomBigInt(max: bigint): bigint {
    const bytes = Math.ceil(max.toString(2).length / 8);
    let r: bigint;
    do {
      const b = new Uint8Array(bytes);
      globalThis.crypto.getRandomValues(b);
      r = this.bytesToBigInt(b);
    } while (r >= max);
    return r;
  }
  public privatekeytoPublicKey(privKey: Uint8Array): [Uint8Array, Uint8Array] {
    const privKeyBigint = this.bytesToBigInt(privKey);
    const pubKey = this.scalarMultG(privKeyBigint);
    return [this.BigintToBytes(pubKey[0]), this.BigintToBytes(pubKey[1])];
  }
}

class p_256 {
  private readonly P: bigint =
    0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
  private readonly a: bigint =
    0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn;
  private readonly b: bigint =
    0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn; // めんどくさー
  private readonly N: bigint =
    0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  private readonly G: [bigint, bigint] = [
    0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
  ];

  public sha256(data: Uint8Array): Uint8Array {
    const K = new Uint32Array([
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]);

    const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));

    let h0 = 0x6a09e667,
      h1 = 0xbb67ae85,
      h2 = 0x3c6ef372,
      h3 = 0xa54ff53a;
    let h4 = 0x510e527f,
      h5 = 0x9b05688c,
      h6 = 0x1f83d9ab,
      h7 = 0x5be0cd19;

    const len = data.length;
    const bitLen = len * 8;
    const blockCount = Math.ceil((len + 9) / 64);
    const blocks = new Uint8Array(blockCount * 64);
    blocks.set(data);
    blocks[len] = 0x80;
    const view = new DataView(blocks.buffer);
    view.setUint32(blocks.length - 8, Math.floor(bitLen / 0x100000000), false);
    view.setUint32(blocks.length - 4, bitLen >>> 0, false);

    for (let i = 0; i < blocks.length; i += 64) {
      const W = new Uint32Array(64);
      for (let t = 0; t < 16; t++) {
        W[t] = view.getUint32(i + t * 4, false);
      }
      for (let t = 16; t < 64; t++) {
        const s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
        const s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
        W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
      }

      let a = h0,
        b = h1,
        c = h2,
        d = h3;
      let e = h4,
        f = h5,
        g = h6,
        h = h7;

      for (let t = 0; t < 64; t++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ ((~e >>> 0) & g); // ✅ ~e を明示的にuint32化
        const temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;

        h = g;
        g = f;
        f = e;
        e = (d + temp1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) >>> 0;
      }

      h0 = (h0 + a) >>> 0;
      h1 = (h1 + b) >>> 0;
      h2 = (h2 + c) >>> 0;
      h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0;
      h5 = (h5 + f) >>> 0;
      h6 = (h6 + g) >>> 0;
      h7 = (h7 + h) >>> 0;
    }

    const result = new Uint8Array(32);
    const rv = new DataView(result.buffer);
    rv.setUint32(0, h0, false);
    rv.setUint32(4, h1, false);
    rv.setUint32(8, h2, false);
    rv.setUint32(12, h3, false);
    rv.setUint32(16, h4, false);
    rv.setUint32(20, h5, false);
    rv.setUint32(24, h6, false);
    rv.setUint32(28, h7, false);
    return result;
  }

  private mod25519(x: bigint): bigint {
    let val = x % this.P;
    if (val < 0n) val += this.P;
    return val;
  }

  private inv(e: bigint, mod: bigint): bigint {
    let r0 = mod,
      r1 = e;
    let x0 = 0n,
      x1 = 1n;

    r1 = r1 % mod;
    if (r1 === 0n) return 0n;

    while (r1 !== 0n) {
      const q = r0 / r1;
      const r = r0 % r1;
      r0 = r1;
      r1 = r;
      const tmp = x0 - q * x1;
      x0 = x1;
      x1 = tmp;
    }

    if (r0 !== 1n) return 0n;
    return x0 < 0n ? x0 + mod : x0;
  }

  public addPoints(P: [bigint, bigint], Q: [bigint, bigint]): [bigint, bigint] {
    const [x1, y1] = P;
    const [x2, y2] = Q;

    if (x1 === 0n && y1 === 0n) return Q;
    if (x2 === 0n && y2 === 0n) return P;

    let m: bigint;

    if (x1 === x2) {
      // 修正: P + (-P) または y1 が 0 (垂直接線) の場合は無限遠点を返す
      if (y1 !== y2 || y1 === 0n) {
        return [0n, 0n];
      }
      const num = this.mod25519(3n * x1 * x1 + this.a);
      const den = this.mod25519(2n * y1);
      m = this.mod25519(num * this.inv(den, this.P));
    } else {
      const num = this.mod25519(y2 - y1);
      const den = this.mod25519(x2 - x1);
      m = this.mod25519(num * this.inv(den, this.P));
    }

    const x3 = this.mod25519(m * m - x1 - x2);
    const y3 = this.mod25519(m * (x1 - x3) - y1);
    return [x3, y3];
  }

  public scalarMult(k: bigint, P: [bigint, bigint]): [bigint, bigint] {
    let R0: [bigint, bigint] = [0n, 0n]; // 無限遠点
    let R1: [bigint, bigint] = P;

    // P-256の位数nが256ビットなので、常に256回ループさせる
    for (let i = 255; i >= 0; i--) {
      const bit = (k >> BigInt(i)) & 1n;
      if (bit === 0n) {
        R1 = this.addPoints(R0, R1);
        R0 = this.addPoints(R0, R0);
      } else {
        R0 = this.addPoints(R0, R1);
        R1 = this.addPoints(R1, R1);
      }
    }
    return R0;
  }
  public isPointOnCurve(P: [bigint, bigint]): boolean {
    const [x, y] = P;
    if (x === 0n && y === 0n) return false;
    const left = this.mod25519(y * y);
    const right = this.mod25519(x ** 3n + this.a * x + this.b);
    return left === right;
  }

  private bigintToHex(n: bigint): string {
    return n.toString(16).padStart(64, "0");
  }

  private hexToBigInt(hex: string): bigint {
    return BigInt("0x" + hex);
  }
  private generateK(message: Uint8Array, privateKey: Uint8Array): bigint {
    const qLen = Math.ceil(this.N.toString(2).length / 8);

    // ステップa: h1 = hash(message)
    const h1 = this.sha256(message);

    // ステップb: V = 0x01 * 32
    let V = new Uint8Array(qLen).fill(0x01);

    // ステップc: K = 0x00 * 32
    let K = new Uint8Array(qLen).fill(0x00);

    // ステップd: K = HMAC-SHA256(K, V || 0x00 || privateKey || h1)
    K = this.hmacSha256(
      K,
      new Uint8Array([...V, 0x00, ...privateKey, ...h1]),
    ) as Uint8Array<ArrayBuffer>;

    // ステップe: V = HMAC-SHA256(K, V)
    V = this.hmacSha256(K, V) as Uint8Array<ArrayBuffer>;

    // ステップf: K = HMAC-SHA256(K, V || 0x01 || privateKey || h1)
    K = this.hmacSha256(
      K,
      new Uint8Array([...V, 0x01, ...privateKey, ...h1]),
    ) as Uint8Array<ArrayBuffer>;

    // ステップg: V = HMAC-SHA256(K, V)
    V = this.hmacSha256(K, V) as Uint8Array<ArrayBuffer>;

    // ステップh: 候補を生成してqの範囲に収まるまで繰り返す
    while (true) {
      // T を空にする
      let T = new Uint8Array(0);

      // T が qLen 以上になるまで V を追加
      while (T.length < qLen) {
        V = this.hmacSha256(K, V) as Uint8Array<ArrayBuffer>;
        T = new Uint8Array([...T, ...V]);
      }

      // k候補を取り出す
      const k = this.bytesToBigInt(T.slice(0, qLen));

      // 1 <= k <= q-1 なら採用
      if (k >= 1n && k < this.N) {
        return k;
      }

      // 範囲外なら K, V を更新して再試行
      K = this.hmacSha256(
        K,
        new Uint8Array([...V, 0x00]),
      ) as Uint8Array<ArrayBuffer>;
      V = this.hmacSha256(K, V) as Uint8Array<ArrayBuffer>;
    }
  }
  private hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
    const BLOCK = 64;
    const k = key.length > BLOCK ? this.sha256(key) : key;
    const kPadded = new Uint8Array(BLOCK);
    kPadded.set(k);
    const ipad = kPadded.map((b) => b ^ 0x36);
    const opad = kPadded.map((b) => b ^ 0x5c);
    return this.sha256(this.concat(opad, this.sha256(this.concat(ipad, data))));
  }
  private concat(...arrays: Uint8Array[]): Uint8Array {
    const total = arrays.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) {
      out.set(a, offset);
      offset += a.length;
    }
    return out;
  }
  private signtobigint(
    message: Uint8Array,
    privateKey: string,
  ): { r: bigint; s: bigint } {
    let k = this.generateK(
      message,
      this.BigintToBytes(this.hexToBigInt(privateKey)),
    );
    const privKey = this.hexToBigInt(privateKey);
    const R = this.scalarMult(k, this.G);
    const r = R[0] % this.N;
    const s =
      (this.inv(k, this.N) *
        ((this.bytesToBigInt(this.sha256(message)) + r * privKey) % this.N)) %
      this.N;

    // 修正: 署名要件として r または s が 0 の場合はエラー
    if (r === 0n || s === 0n) {
      throw new Error(
        "署名値が0になりました。アルゴリズム要件により失敗とみなします。",
      );
    }
    return { r, s };
  }

  public sign(
    message: Uint8Array,
    privateKey: Uint8Array,
  ): [Uint8Array, Uint8Array] {
    const { r, s } = this.signtobigint(
      message,
      this.bigintToHex(this.bytesToBigInt(privateKey)),
    );
    return [this.BigintToBytes(r), this.BigintToBytes(s)] as [
      Uint8Array,
      Uint8Array,
    ];
  }

  public verify(
    message: Uint8Array,
    signature: [Uint8Array, Uint8Array],
    publicKey: [Uint8Array, Uint8Array],
  ): boolean {
    if (
      this.isPointOnCurve([
        this.bytesToBigInt(publicKey[0]),
        this.bytesToBigInt(publicKey[1]),
      ]) === false
    ) {
      throw new Error("無効な公開鍵: 曲線上にありません");
    }
    const r = this.bytesToBigInt(signature[0]);
    const s = this.bytesToBigInt(signature[1]);
    if (r <= 0n || r >= this.N || s <= 0n || s >= this.N) return false;
    const w = this.inv(s, this.N);
    const u1 = (this.bytesToBigInt(this.sha256(message)) * w) % this.N;
    const u2 = (r * w) % this.N;
    const P1 = this.scalarMult(u1, this.G);
    const P2 = this.scalarMult(u2, [
      this.bytesToBigInt(publicKey[0]),
      this.bytesToBigInt(publicKey[1]),
    ]);
    const X = this.addPoints(P1, P2);
    return X[0] % this.N === r;
  }

  public generateKeyPair(): { privateKey: string; publicKey: string } {
    const privateKey = this.getRandomBigInt(this.N - 1n) + 1n;
    const pubPoint = this.scalarMult(privateKey, this.G);
    const uncompressed =
      this.bigintToHex(pubPoint[0]) + this.bigintToHex(pubPoint[1]);
    return {
      privateKey: this.bigintToHex(privateKey),
      publicKey: "04" + uncompressed,
    };
  }

  private BigintToBytes(n: bigint): Uint8Array {
    const hex = n.toString(16).toUpperCase().padStart(64, "0");
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  private bytesToBigInt(bytes: Uint8Array): bigint {
    const len = bytes.length;
    let res = 0n;
    const view = new DataView(bytes.buffer, bytes.byteOffset, len);

    let i = 0;
    for (; i <= len - 8; i += 8) {
      res = (res << 64n) + view.getBigUint64(i);
    }
    for (; i < len; i++) {
      res = (res << 8n) + BigInt(bytes[i]);
    }
    return res;
  }

  private modSqrt(n: bigint): bigint {
    if (n === 0n) return 0n;
    // 修正: 平方剰余かどうかの事前確認。これにより無限ループと指数エラーを防ぐ。
    if (this.modPow(n, (this.P - 1n) / 2n) !== 1n) {
      throw new Error("平方根が存在しません");
    }

    let Q = this.P - 1n;
    let S = 0n;
    while (Q % 2n === 0n) {
      Q /= 2n;
      S++;
    }

    let z = 2n;
    while (this.modPow(z, (this.P - 1n) / 2n) !== this.P - 1n) {
      z++;
    }

    let M = S;
    let c = this.modPow(z, Q);
    let t = this.modPow(n, Q);
    let R = this.modPow(n, (Q + 1n) / 2n);

    while (true) {
      if (t === 1n) return R;
      let i = 1n;
      let tmp = (t * t) % this.P;
      while (tmp !== 1n) {
        tmp = (tmp * tmp) % this.P;
        i++;
      }
      const b = this.modPow(c, 2n ** (M - i - 1n));
      M = i;
      c = (b * b) % this.P;
      t = (t * b * b) % this.P;
      R = (R * b) % this.P;
    }
  }

  private modPow(base: bigint, exp: bigint): bigint {
    let result = 1n;
    base = base % this.P;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % this.P;
      base = (base * base) % this.P;
      exp >>= 1n;
    }
    return result;
  }

  public compressPublicKey(publicKey: string): string {
    const x = this.hexToBigInt(publicKey.slice(0, 64));
    const y = this.hexToBigInt(publicKey.slice(64, 128));
    const prefix = y % 2n === 0n ? "02" : "03";
    return prefix + this.bigintToHex(x);
  }

  public decompressPublicKey(compressed: string): string {
    const prefix = compressed.slice(0, 2);
    const x = this.hexToBigInt(compressed.slice(2, 66));
    const rhs = this.mod25519(x * x * x + this.a * x + this.b);
    const y = this.modSqrt(rhs);
    const isOdd = y % 2n === 1n;
    const wantOdd = prefix === "03";
    const finalY = isOdd === wantOdd ? y : this.P - y;
    return this.bigintToHex(x) + this.bigintToHex(finalY);
  }

  private getRandomBigInt(max: bigint): bigint {
    const bytes = Math.ceil(max.toString(2).length / 8);
    let rand: bigint;
    do {
      const buf = new Uint8Array(bytes);
      globalThis.crypto.getRandomValues(buf);
      rand = this.bytesToBigInt(buf);
    } while (rand >= max);
    return rand;
  }

  public privateKeyToPublicKey(
    privateKeyHex: Uint8Array,
  ): [Uint8Array, Uint8Array] {
    const privKey: bigint = this.bytesToBigInt(privateKeyHex);
    if (privKey <= 0n || privKey >= this.N) throw new Error("無効な秘密鍵");
    const pubPoint = this.scalarMult(privKey, this.G);
    const uncompressed: [Uint8Array, Uint8Array] = [
      this.BigintToBytes(pubPoint[0]),
      this.BigintToBytes(pubPoint[1]),
    ];
    return uncompressed;
  }
  public ecdh(privateKeyHex: string, peerPublicKeyHex: string): string {
    const privKey: bigint = this.hexToBigInt(privateKeyHex);
    if (privKey <= 0n || privKey >= this.N) throw new Error("無効な秘密鍵");
    let uncompressed: string;
    if (peerPublicKeyHex.length === 66) {
      uncompressed = this.decompressPublicKey(peerPublicKeyHex);
    } else if (
      peerPublicKeyHex.length === 130 &&
      peerPublicKeyHex.startsWith("04")
    ) {
      uncompressed = peerPublicKeyHex.slice(2);
    } else {
      uncompressed = peerPublicKeyHex;
    }
    const peerX = this.hexToBigInt(uncompressed.slice(0, 64));
    const peerY = this.hexToBigInt(uncompressed.slice(64, 128));
    if (!this.isPointOnCurve([peerX, peerY])) {
      throw new Error("無効な公開鍵");
    }
    const sharedPoint = this.scalarMult(privKey, [peerX, peerY]);
    return this.bigintToHex(sharedPoint[0]);
  }
}

const jwt = new myjwt();
const key = globalThis.crypto.getRandomValues(new Uint8Array(32));
// HMAC_SHA256 SchnorrP256 ECDSA_P256
const jwtToken = jwt.createJWT(
  "HMAC_SHA256",
  {
	"certificate": {
		"DYLA": [
			{
				"CA": "ShudoPhysicsRootCA",
				"Order": 0,
				"Domain": {
					"CN": "rootCA",
					"IsCA": true,
					"Pubkey": "04b0781986d589cb8dcf220c50b8ea6cedd4a6a70710e310b2b221f855636ac8874d35454255acb259cee954868d4b87a5abd33370aebbe74c965d9f086141aeff",
					"Country": "JP",
					"State": "",
					"City": "",
					"IssuedAt": "2026-03-07T04:50:31Z"
				},
				"Sig": "7cc12349371e4bf5a14a880c5821862c54f8bdbd687d0a930a24e32982096f83d3539505b427ec4f9b90b5ac11257683702e76317699c604facea499e595a60f",
				"Text": "",
				"Message": "Do you like apple?",
				"Serial": "400c621e3e7fb765edcc05f740c8840dd84bf4bbb20301a8d9cc5b1d754bc150"
			}
		]
	},
	"public": "xxxxxxxxxxxxxxxxxx"
},
  key,
);
console.log("JWT Token:", jwtToken);
let pubkey;
if (!jwtToken.publickey) {
  pubkey = key;
} else {
  pubkey = jwtToken.publickey;
}
const isValid = jwt.verifyJWT(jwtToken.token, pubkey);
console.log("Is JWT valid?", isValid);
