export class PointPairSchnorrP256 {
  private readonly P =
    0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
  private readonly N =
    0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  private readonly G: [bigint, bigint] = [
    0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
  ];

  private readonly G_precomp_window: [bigint, bigint, bigint][][] = (() => {
    const table: [bigint, bigint, bigint][][] = [];
    let base: [bigint, bigint, bigint] = [this.G[0], this.G[1], 1n];
    for (let i = 0; i < 32; i++) {
      const row: [bigint, bigint, bigint][] = new Array(256);
      row[0] = [0n, 1n, 0n];
      row[1] = base;
      for (let j = 2; j < 256; j++)
        row[j] = this.addPointsJacobian(row[j - 1], base);
      table.push(row);
      for (let j = 0; j < 8; j++) base = this.doubleJacobian(base);
    }
    return table;
  })();

  private addPointsJacobian(
    P1: [bigint, bigint, bigint],
    Q: [bigint, bigint, bigint],
  ): [bigint, bigint, bigint] {
    const [X1, Y1, Z1] = P1;
    const [X2, Y2, Z2] = Q;
    if (Z1 === 0n) return Q;
    if (Z2 === 0n) return P1;
    const p = this.P;

    const Z1Z1 = (Z1 * Z1) % p;
    const Z2Z2 = (Z2 * Z2) % p;

    const U1 = (X1 * Z2Z2) % p;
    const U2 = (X2 * Z1Z1) % p;

    // S1 = Y1 * Z2^3, S2 = Y2 * Z1^3
    const Z2_cu = (Z2Z2 * Z2) % p;
    const Z1_cu = (Z1Z1 * Z1) % p;
    const S1 = (Y1 * Z2_cu) % p;
    const S2 = (Y2 * Z1_cu) % p;

    const H = (U2 - U1 + p) % p;
    const RR = (S2 - S1 + p) % p;

    if (H === 0n) {
      if (RR === 0n) return this.doubleJacobian(P1);
      return [0n, 1n, 0n];
    }

    const HH = (H * H) % p;
    const HHH = (HH * H) % p;
    const U1HH = (U1 * HH) % p;

    const X3 = (RR * RR - HHH - 2n * U1HH) % p;
    const X3n = (X3 + p) % p; // normalize once

    const Y3 = (RR * (U1HH - X3n + p) - S1 * HHH) % p;
    const Z3 = (H * Z1) % p;
    const Z3n = (Z3 * Z2) % p;

    return [X3n, (Y3 + p) % p, Z3n];
  }

  // ─── ヤコビアン点2倍算 ───────────────────────────────────────────────────
  // a = P-3 専用最適化: M = 3(X+Z²)(X-Z²)
  private doubleJacobian(
    Pt: [bigint, bigint, bigint],
  ): [bigint, bigint, bigint] {
    const [X, Y, Z] = Pt;
    if (Z === 0n) return Pt;
    const p = this.P;
    const YY = (Y * Y) % p;
    const YYYY = (YY * YY) % p;
    const ZZ = (Z * Z) % p;
    const S = (4n * X * YY) % p;
    const M = (3n * ((X + ZZ) % p) * ((X - ZZ + p) % p)) % p;
    const X3 = (M * M - 2n * S + 2n * p) % p;
    const Y3 = (M * ((S - X3 + p) % p) - 8n * YYYY + 8n * p) % p;
    return [X3, Y3, (2n * Y * Z) % p];
  }

  private toAffine(Pt: [bigint, bigint, bigint]): [bigint, bigint] {
    if (Pt[2] === 0n) return [0n, 0n];
    const invZ = this.inv(Pt[2], this.P);
    const invZ2 = (invZ * invZ) % this.P;
    const invZ3 = (invZ2 * invZ) % this.P;
    return [(Pt[0] * invZ2) % this.P, (Pt[1] * invZ3) % this.P];
  }

  private scalarMultGJac(k: bigint): [bigint, bigint, bigint] {
    const win0 = Number(k & 0xffn);
    let R: [bigint, bigint, bigint] = [...this.G_precomp_window[0][win0]];
    for (let i = 8; i < 256; i += 8) {
      const win = Number((k >> BigInt(i)) & 0xffn);
      R = this.addPointsJacobian(R, this.G_precomp_window[i >> 3][win]);
    }
    return R;
  }
  private scalarMultG(k: bigint): [bigint, bigint] {
    return this.toAffine(this.scalarMultGJac(k));
  }

  private inv(a: bigint, m: bigint): bigint {
    a %= m;
    if (a < 0n) a += m;
    if (a === 0n) throw new Error("inv: a == 0");

    let t = 0n,
      newT = 1n;
    let r = m,
      newR = a;

    while (newR !== 0n) {
      const q = r / newR;

      // (t, newT) = (newT, t - q*newT)
      const t0 = t;
      t = newT;
      newT = t0 - q * newT;

      // (r, newR) = (newR, r - q*newR)
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
    // y² ≡ x³ - 3x + b  (a = p-3)
    const rhs =
      (((x2 * x) % p) -
        ((3n * x) % p) +
        0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn +
        2n * p) %
      p;
    return (y * y) % p === rhs;
  }

  private signBigint(
    message: bigint,
    privKey: bigint,
  ): [[bigint, bigint], bigint] {
    const mB = this.BigintToBytes(message);
    const xB = this.BigintToBytes(privKey);

    const k = this.generateK(mB, xB);
    const R = this.scalarMultG(k);

    const RxB = this.BigintToBytes(R[0]);
    const RyB = this.BigintToBytes(R[1]);

    const e =
      this.bytesToBigInt(this.sha256(this.concat(RxB, RyB, mB))) % this.N;

    if (e === 0n) throw new Error("e==0, retry");

    const s = ((k + privKey) * this.inv(e, this.N)) % this.N;
    return [R, s];
  }

  public sign(
    message: Uint8Array,
    privKey: Uint8Array,
  ): [Uint8Array, Uint8Array, Uint8Array] {
    const messageBigint = this.bytesToBigInt(message);
    const privKeyBigint = this.bytesToBigInt(privKey);
    const [R, s] = this.signBigint(messageBigint, privKeyBigint);
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
    if (!this.isPointOnCurve(pubKeyBigint)) return false;
    if (!this.isPointOnCurve(R)) return false;
    const e =
      this.bytesToBigInt(
        this.sha256(
          this.concat(
            this.BigintToBytes(R[0]),
            this.BigintToBytes(R[1]),
            this.BigintToBytes(messageBigint),
          ),
        ),
      ) % this.N;
    const s = (this.bytesToBigInt(signature[2]) * e) % this.N;
    const sg = this.scalarMultGJac(s);
    const Rj: [bigint, bigint, bigint] = [R[0], R[1], 1n];
    const Yj: [bigint, bigint, bigint] = [pubKeyBigint[0], pubKeyBigint[1], 1n];
    const right = this.addPointsJacobian(Rj, Yj);
    const left = sg;

    return this.equalsJacobian(left, right);
  }
  private equalsJacobian(
    A: [bigint, bigint, bigint],
    B: [bigint, bigint, bigint],
  ): boolean {
    const [X1, Y1, Z1] = A;
    const [X2, Y2, Z2] = B;
    if (Z1 === 0n || Z2 === 0n) return Z1 === 0n && Z2 === 0n;

    const p = this.P;

    // fast path: if both affine (Z=1), compare directly
    if (Z1 === 1n && Z2 === 1n) {
      return X1 % p === X2 % p && Y1 % p === Y2 % p;
    }

    // fast path: if one is affine
      if (Z1 === 1n) {
      const Z2Z2 = (Z2 * Z2) % p;
      const U1 = (X1 * Z2Z2) % p; // X1はAffineのxそのもの
      const U2 = X2 % p;          // X2は比較対象のJacobian X
      if (U1 !== U2) return false;

      const Z2Z2Z2 = (Z2Z2 * Z2) % p;
      const S1 = (Y1 * Z2Z2Z2) % p;
      const S2 = Y2 % p;
      return S1 === S2;
    }

    // generic path (your original)
    const Z1Z1 = (Z1 * Z1) % p;
    const Z2Z2 = (Z2 * Z2) % p;
    const U1 = (X1 * Z2Z2) % p;
    const U2 = (X2 * Z1Z1) % p;
    if (U1 !== U2) return false;
    const Z1Z1Z1 = (Z1Z1 * Z1) % p;
    const Z2Z2Z2 = (Z2Z2 * Z2) % p;
    const S1 = (Y1 * Z2Z2Z2) % p;
    const S2 = (Y2 * Z1Z1Z1) % p;
    return S1 === S2;
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

  // ─── HMAC-SHA256 ─────────────────────────────────────────────────────────
  // ★ map() → for ループ (コールバック生成コスト削減)
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

  // ─── RFC 6979 決定論的 k 生成 ────────────────────────────────────────────
  // ★ [...V, 0x00, ...key, ...h1] → concat() (spread は O(n) Array 経由コピー)
  private generateK(message: Uint8Array, privateKey: Uint8Array): bigint {
    const qLen = 32,
      h1 = this.sha256(message);
    let V = new Uint8Array(qLen).fill(0x01);
    let K = new Uint8Array(qLen).fill(0x00);
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

  // ─── concat ──────────────────────────────────────────────────────────────
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
// ============================================================
//  統計ベンチマーク: min / max / mean / median / p95 / p99 / stddev
// ============================================================
async function test() {
  function stats(samples: number[]) {
    const sorted = [...samples].sort((a, b) => a - b);
    const n = sorted.length;
    const mean = samples.reduce((s, v) => s + v, 0) / n;
    const variance = samples.reduce((s, v) => s + (v - mean) ** 2, 0) / n;
    const stddev = Math.sqrt(variance);
    const pct = (p: number) => {
      const idx = Math.ceil((p / 100) * n) - 1;
      return sorted[Math.max(0, Math.min(n - 1, idx))];
    };
    return {
      min: sorted[0],
      p25: pct(25),
      median: pct(50),
      mean,
      p75: pct(75),
      p95: pct(95),
      p99: pct(99),
      max: sorted[n - 1],
      stddev,
    };
  }

  function fmt(v: number) {
    return v.toFixed(4) + "ms";
  }

  function printStats(label: string, s: ReturnType<typeof stats>) {
    console.log(`\n── ${label} ──`);
    console.log(`  min    : ${fmt(s.min)}`);
    console.log(`  p25    : ${fmt(s.p25)}`);
    console.log(`  median : ${fmt(s.median)}`);
    console.log(`  mean   : ${fmt(s.mean)}`);
    console.log(`  p75    : ${fmt(s.p75)}`);
    console.log(`  p95    : ${fmt(s.p95)}`);
    console.log(`  p99    : ${fmt(s.p99)}`);
    console.log(`  max    : ${fmt(s.max)}`);
    console.log(`  stddev : ${fmt(s.stddev)}`);
  }

  const dsa = new PointPairSchnorrP256();
  const encoder = new TextEncoder();
  const message = encoder.encode("Hello, ECDSA!");
  const ITERATIONS = 5000;

  const { privateKey, publicKey } = dsa.generateKeyPair();
  const signature = dsa.sign(message, privateKey);

  // ================================================================
  //  自作署名
  // ================================================================
  console.log(`\n${"=".repeat(50)}`);
  console.log(`  自作署名  (n=${ITERATIONS.toLocaleString()})`);
  console.log("=".repeat(50));

  const selfSignSamples: number[] = [];
  for (let i = 0; i < ITERATIONS; i++) {
    const t0 = performance.now();
    dsa.sign(message, privateKey);
    selfSignSamples.push(performance.now() - t0);
  }

  const selfVerifySamples: number[] = [];
  for (let i = 0; i < ITERATIONS; i++) {
    const t0 = performance.now();
    dsa.verify(message, publicKey, signature);
    selfVerifySamples.push(performance.now() - t0);
  }

  printStats("署名", stats(selfSignSamples));
  printStats("検証", stats(selfVerifySamples));

  // ================================================================
  //  WebCrypto ECDSA P-256
  // ================================================================
  console.log(`\n${"=".repeat(50)}`);
  console.log(`  WebCrypto ECDSA P-256  (n=${ITERATIONS.toLocaleString()})`);
  console.log("=".repeat(50));

  const ecKeyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const ecSig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    ecKeyPair.privateKey,
    message,
  );

  const ecSignSamples: number[] = [];
  for (let i = 0; i < ITERATIONS; i++) {
    const t0 = performance.now();
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      ecKeyPair.privateKey,
      message,
    );
    ecSignSamples.push(performance.now() - t0);
  }

  const ecVerifySamples: number[] = [];
  for (let i = 0; i < ITERATIONS; i++) {
    const t0 = performance.now();
    await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      ecKeyPair.publicKey,
      ecSig,
      message,
    );
    ecVerifySamples.push(performance.now() - t0);
  }

  printStats("署名", stats(ecSignSamples));
  printStats("検証", stats(ecVerifySamples));
  // ================================================================
  //  比率サマリ (mean ベース)
  // ================================================================
  const ss = stats(selfSignSamples);
  const sv = stats(selfVerifySamples);
  const es = stats(ecSignSamples);
  const ev = stats(ecVerifySamples);

  console.log(`\n${"=".repeat(50)}`);
  console.log("  比率サマリ (mean ベース)");
  console.log("=".repeat(50));
  console.log(
    `自作 vs WebCrypto ECDSA  署名: ${(ss.mean / es.mean).toFixed(1)}倍   検証: ${(sv.mean / ev.mean).toFixed(1)}倍`,
  );
}

// ================================================================
//  正当性チェック
// ================================================================
const dsa = new PointPairSchnorrP256();
const encoder = new TextEncoder();
const message = encoder.encode("Hello, ECDSA!");
const { privateKey, publicKey } = dsa.generateKeyPair();
console.time("sign");
const signature = dsa.sign(message, privateKey);
console.timeEnd("sign");
const fakeResult = dsa.verify(
  encoder.encode("Fake message!"),
  publicKey,
  signature,
);
console.time("verify");
const trueResult = dsa.verify(message, publicKey, signature);
console.timeEnd("verify");
console.log(`\n不正署名: ${fakeResult}`);
console.log(`正当な署名: ${trueResult}`);
test();