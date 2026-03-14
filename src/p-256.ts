export class p_256 {
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

  public sign(message: Uint8Array, privateKey: string): string {
    const { r, s } = this.signtobigint(message, privateKey);
    return this.bigintToHex(r) + this.bigintToHex(s);
  }

  public verify(
    message: Uint8Array,
    signature: string,
    publicKey: string,
  ): boolean {
    let uncompressed: string;
    if (publicKey.length === 66) {
      uncompressed = this.decompressPublicKey(publicKey);
    } else if (publicKey.length === 130 && publicKey.startsWith("04")) {
      uncompressed = publicKey.slice(2);
    } else {
      uncompressed = publicKey;
    }
    if (
      this.isPointOnCurve([
        this.hexToBigInt(uncompressed.slice(0, 64)),
        this.hexToBigInt(uncompressed.slice(64, 128)),
      ]) === false
    ) {
      throw new Error("無効な公開鍵: 曲線上にありません");
    }
    const rHex = signature.slice(0, 64).padStart(64, "0");
    const sHex = signature.slice(64, 128).padStart(64, "0");
    const r = this.hexToBigInt(rHex);
    const s = this.hexToBigInt(sHex);
    if (r <= 0n || r >= this.N || s <= 0n || s >= this.N) return false;
    const w = this.inv(s, this.N);
    const u1 = (this.bytesToBigInt(this.sha256(message)) * w) % this.N;
    const u2 = (r * w) % this.N;
    const P1 = this.scalarMult(u1, this.G);
    const P2 = this.scalarMult(u2, [
      this.hexToBigInt(uncompressed.slice(0, 64)),
      this.hexToBigInt(uncompressed.slice(64, 128)),
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

  public privateKeyToPublicKey(privateKeyHex: string): {
    compressed: string;
    uncompressed: string;
  } {
    const privKey: bigint = this.hexToBigInt(privateKeyHex);
    if (privKey <= 0n || privKey >= this.N) throw new Error("無効な秘密鍵");
    const pubPoint = this.scalarMult(privKey, this.G);
    const uncompressed =
      this.bigintToHex(pubPoint[0]) + this.bigintToHex(pubPoint[1]);
    return {
      compressed: this.compressPublicKey(uncompressed),
      uncompressed,
    };
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
