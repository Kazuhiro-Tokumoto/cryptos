class what_is_this {
  private modPow(base: bigint, exp: bigint, mod: bigint): bigint {
    const bitLength = (n: bigint): number => n.toString(2).length;
    const modBits = bitLength(mod);
    function windowModPow(
      base: bigint,
      exponent: bigint,
      modulus: bigint,
    ): bigint {
      if (modulus === 1n) return 0n;
      if (exponent === 0n) return 1n; // 指数0のケースを明示

      // 負の基数に対応し、初期の剰余をとる
      let b = ((base % modulus) + modulus) % modulus;
      let e = exponent;
      let result = 1n;

      while (e > 0n) {
        // LSBが1の場合のみ乗算
        if ((e & 1n) === 1n) {
          result = (result * b) % modulus;
        }

        e >>= 1n;

        // 指数がまだ残っている場合のみ自乗を計算（最後の無駄を省く）
        if (e > 0n) {
          b = (b * b) % modulus;
        }
      }

      return result;
    }
    let k: number;
    if (modBits >= 131072) {
      k = 13;
    } else if (modBits >= 65536) {
      k = 12;
    } else if (modBits >= 32768) {
      k = 11;
    } else if (modBits >= 16384) {
      k = 10;
    } else if (modBits >= 8192) {
      k = 9;
    } else if (modBits >= 4096) {
      k = 8;
    } else if (modBits >= 2048) {
      k = 7;
    } else if (modBits >= 1024) {
      k = 6;
    } else if (modBits >= 512) {
      k = 5;
    } else if (modBits >= 256) {
      k = 4;
    } else if (modBits >= 128) {
      k = 3;
    } else {
      k = 2;
    }
    if (mod % 2n === 0n) {
      console.log(
        "Warning: Modulus is even. This implementation assumes an odd modulus for Montgomery reduction.",
      );
      return windowModPow(base, exp, mod);
    }
    const wsize = k;
    const numOdd = 1 << (wsize - 1);

    const R = 1n << BigInt(modBits);
    const mask = R - 1n;

    // nPrime計算
    let nPrime = mod & mask;
    for (let i = 0; i < Math.ceil(modBits / 64); i++) {
      nPrime = (nPrime * (2n - ((mod * nPrime) & mask))) & mask;
    }
    nPrime = (R - nPrime) & mask;

    // Montgomery reduction
    const montReduce = (T: bigint): bigint => {
      const u = ((T & mask) * nPrime) & mask;
      const x = (T + u * mod) >> BigInt(modBits);
      return x >= mod ? x - mod : x;
    };

    // テーブル生成
    const baseBar = (base << BigInt(modBits)) % mod;
    const baseBar2 = montReduce(baseBar * baseBar);
    const table = new Array<bigint>(numOdd);
    table[0] = baseBar;
    for (let i = 1; i < numOdd; i++) {
      table[i] = montReduce(table[i - 1] * baseBar2);
    }
    // -- Montgomery法通常べき乗部 --
    // expのbit列をstring化
    const expBin = exp.toString(2);
    let res = (1n << BigInt(modBits)) % mod;

    for (let i = 0; i < expBin.length; ) {
      if (expBin[i] === "0") {
        res = montReduce(res * res);
        i++;
        continue;
      }
      let winLen = Math.min(wsize, expBin.length - i);
      while (winLen > 1 && expBin[i + winLen - 1] === "0") {
        winLen--;
      }
      const winVal = parseInt(expBin.slice(i, i + winLen), 2);
      for (let j = 0; j < winLen; j++) {
        res = montReduce(res * res);
      }
      if (winVal > 0) {
        res = montReduce(res * table[(winVal - 1) >> 1]);
      }
      i += winLen;
    }
    return montReduce(res);
  }

  private gcd(a: bigint, b: bigint): bigint {
    let x = a < 0n ? -a : a;
    let y = b < 0n ? -b : b;

    while (y !== 0n) {
      x %= y;
      // 分割代入で入れ替え
      [x, y] = [y, x];
    }
    return x;
  }

  private lcm(a: bigint, b: bigint): bigint {
    if (a === 0n || b === 0n) return 0n;

    const absA = a < 0n ? -a : a;
    const absB = b < 0n ? -b : b;

    // 先に gcd で割ることで、(a * b) による巨大な数値の生成を抑える
    return (absA / this.gcd(absA, absB)) * absB;
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

  private sha256(data: Uint8Array): Uint8Array {
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

  private isProbablyPrime(n: bigint, k: number = 15): boolean {
    if (n <= 3n) return n > 1n;
    if (!(n & 1n)) return false;

    let d = n - 1n;
    let s = 0;
    while (!(d & 1n)) {
      d >>= 1n;
      s++;
    }

    const nm1 = n - 1n;
    const bases = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];

    for (let i = 0; i < k; i++) {
      const a = i < bases.length ? bases[i] : this.rnd(nm1);
      let x = this.modPow(a, d, n);

      if (x === 1n || x === nm1) continue;

      let composite = true;
      for (let r = 1; r < s; r++) {
        x = this.modPow(x, 2n, n);

        if (x === nm1) {
          composite = false;
          break;
        }
        if (x === 1n) return false;
      }

      if (composite) return false;
    }

    return true;
  }

  private rnd(n: bigint): bigint {
    const bitLengths = this.bitLength(n);
    const byteLength = (bitLengths + 7) >> 3;
    const uint8 = new Uint8Array(byteLength);

    while (true) {
      globalThis.crypto.getRandomValues(uint8);
      const num = this.bytesToBigInt(uint8) & ((1n << BigInt(bitLengths)) - 1n);
      if (num > 0n && num < n) return num;
    }
  }
  private bitLength(n: bigint): number {
    return n.toString(2).length;
  }
  private generatePrime(bits: number): bigint {
    while (true) {
      let n = this.rnd(1n << BigInt(bits));
      n |= 1n;
      if (this.isProbablyPrime(n, 1) && this.isProbablyPrime(n, 19)) return n;
    }
  }
  public generateKey(bits: number = 2048): { n: Uint8Array; e: Uint8Array } {
    const p = this.generatePrime(bits >> 1);
    const q = this.generatePrime(bits >> 1);
    const phi = this.lcm(p - 1n, q - 1n);
    return { n: this.bigIntToBytes(p * q), e: this.bigIntToBytes(phi - 1n) };
  }
  private pq(n: bigint, val: bigint): { p: bigint; q: bigint } | null {
    function bigIntSqrt(value: bigint): bigint {
      if (value < 0n) return -1n;
      if (value < 2n) return value;

      let x = value / 2n + 1n;
      let y = (x + value / x) / 2n;
      while (y < x) {
        x = y;
        y = (x + value / x) / 2n;
      }
      return x;
    }
    const candidates = [1n];
    for (let i = 2n; i <= 1000n; i += 2n) candidates.push(i);

    for (const g of candidates) {
      const phi = val * g;
      const sumPQ = n - phi + 1n; // p + q

      // 判別式 D = (p+q)^2 - 4n
      const D = sumPQ * sumPQ - 4n * n;

      if (D < 0n) continue;

      const sqrtD = bigIntSqrt(D);
      if (sqrtD * sqrtD === D) {
        const p = (sumPQ + sqrtD) / 2n;
        const q = (sumPQ - sqrtD) / 2n;

        // 検算
        if (p * q === n) {
          return {
            p,
            q,
          };
        }
      }
    }
    return null;
  }
  public keytopq(
    n: Uint8Array,
    e: Uint8Array,
  ): { p: bigint; q: bigint } | null {
    const phi = this.bytesToBigInt(e) + 1n;
    return this.pq(this.bytesToBigInt(n), phi);
  }
  private encryptbigint(
    message: bigint,
    n: bigint,
    e: bigint,
  ): { iv: bigint; ciphertext: bigint } {
    if (message <= 0n || message >= n || n <= 1n || e <= 0n || e >= n) {
      throw new Error("Message must be in the range (0, n)");
    }
    function bitLength(n: bigint): number {
      return n.toString(2).length;
    }
    const bytesToBigInt = this.bytesToBigInt;
    function rnd(n: bigint): bigint {
      const bitLengths = bitLength(n);
      const byteLength = (bitLengths + 7) >> 3;
      const uint8 = new Uint8Array(byteLength);

      while (true) {
        globalThis.crypto.getRandomValues(uint8);
        const num = bytesToBigInt(uint8) & ((1n << BigInt(bitLengths)) - 1n);
        if (num > 0n && num < n) return num;
      }
    }
    function safeIvMaker(
      message: bigint,
      n: bigint,
    ): { iv: bigint; xormessage: bigint } {
      // n のビット長を取得（例: 4096）
      const nBits = n.toString(2).length;
      // 安全のため、nより確実に小さくなるようにビット数を1つ減らす
      const safeBits = BigInt(nBits - 1);

      // 1. 128bitの種(Seed)を生成
      const seed = rnd(1n << 128n);

      // 2. 種を safeBits 分まで繰り返して巨大なIVを作る
      let fullIv = 0n;
      for (let i = 0n; i < safeBits; i += 128n) {
        fullIv = (fullIv << 128n) | seed;
      }

      // 3. n未満を保証するためのマスクを適用
      const mask = (1n << safeBits) - 1n;
      const iv = fullIv & mask;

      // 4. メッセージもマスクしてからXOR（これで絶対に n を超えない）
      const xormessage = (message & mask) ^ iv;

      // 万が一 0n になった場合のみ最低限の調整（基本は一発で決まる）
      return {
        iv: iv === 0n ? 1n : iv,
        xormessage: xormessage === 0n ? 1n : xormessage,
      };
    }

    const { iv, xormessage } = safeIvMaker.call(this, message, n);



    const ciphertext = this.modPow(xormessage, e, n) 
    return { iv, ciphertext };
  }
  private decryptbigint(
    { iv, ciphertext }: { iv: bigint; ciphertext: bigint },
    n: bigint,
    e: bigint,
  ): bigint {
    // 1. バリデーション（nの最小値などは呼び出し側で保証されているなら簡略化可）
    if (ciphertext <= 0n || ciphertext >= n || iv <= 0n || iv >= n || n <= 1n) {
      throw new Error("Invalid input range");
    }

const xormessage = this.modPow(ciphertext, e, n);

    // 3. 暗号化時と同じルールで IV を引き延ばす
    const nBits = n.toString(2).length;
    const safeBits = BigInt(nBits - 1);

    let fullIv = 0n;
    // 暗号化で使った seed (iv) を繰り返して 4096bit 級の帯を作る
    for (let i = 0n; i < safeBits; i += 128n) {
      fullIv = (fullIv << 128n) | iv;
    }

    const mask = (1n << safeBits) - 1n;
    const expandedIv = fullIv & mask;

    // 4. 引き延ばした IV で XOR してメッセージを復元
    const message = xormessage ^ expandedIv;

    return message;
  }
  private signbigint(message: bigint, n: bigint, e: bigint): bigint {
    if (n <= 1n || e <= 0n || e >= n) {
      throw new Error("Message must be in the range (0, n)");
    }
    const signaturemessage = this.bytesToBigInt(this.sha256(this.bigIntToBytes(message)));
    
    const sign = this.modPow(signaturemessage, e, n);
    return sign
  }
  private bigIntToBytes(n: bigint, size?: number): Uint8Array {
    if (n === 0n) {
      return size ? new Uint8Array(size) : new Uint8Array([0]);
    }

    const bitLength = this.bitLength(n);
    const minByteLength = (bitLength + 7) >> 3;

    if (size === undefined) {
      const u8 = new Uint8Array(minByteLength);
      let tempN = n;
      for (let i = minByteLength - 1; i >= 0; i--) {
        u8[i] = Number(tempN & 0xffn);
        tempN >>= 8n;
      }
      return u8;
    }

    if (minByteLength > size) {
      throw new Error(
        `数値が大きすぎます: ${minByteLength}バイト必要、${size}バイト指定`,
      );
    }

    const u8 = new Uint8Array(size);
    let tempN = n;
    for (let i = size - 1; i >= size - minByteLength; i--) {
      u8[i] = Number(tempN & 0xffn);
      tempN >>= 8n;
    }
    return u8;
  }
  private verifybigint(
    signature: bigint,
    message: bigint,
    n: bigint,
    e: bigint,
  ): boolean {
    if (
      signature <= 0n ||
      signature >= n ||
      message <= 0n ||
      message >= n ||
      n <= 1n ||
      e <= 0n ||
      e >= n
    ) {
      throw new Error("Signature and message must be in the range (0, n)");
    }
    
    const expectedMessage = this.modPow(signature, e, n);
    return (
      expectedMessage ===
      this.bytesToBigInt(this.sha256(this.bigIntToBytes(message)))
    );
  }
  public encrypt(
    message: Uint8Array,
    n: Uint8Array,
    e: Uint8Array,
  ): Uint8Array {
    const m = this.bytesToBigInt(message);
    const N = this.bytesToBigInt(n);
    const E = this.bytesToBigInt(e);
    const { iv, ciphertext } = this.encryptbigint(m, N, E);
    const ivBytes = this.bigIntToBytes(iv, N.toString().length); // IVは128bit（16バイト）で固定
    const ctBytes = this.bigIntToBytes(
      ciphertext,
      this.bigIntToBytes(N).length,
    );
    return new Uint8Array([...ivBytes, ...ctBytes]);
  }
  public decrypt(
    encrypted: Uint8Array,
    n: Uint8Array,
    e: Uint8Array,
  ): Uint8Array {
    const N = this.bytesToBigInt(n);
    const E = this.bytesToBigInt(e);
    const data = new Uint8Array([...encrypted]);
    const ivBytes = data.subarray(0, N.toString().length); // 最初の16バイトがIV
    const ctBytes = data.subarray(N.toString().length); // 残りが暗号文
    const iv = this.bytesToBigInt(ivBytes);
    const ciphertext = this.bytesToBigInt(ctBytes);
    const message = this.decryptbigint({ iv, ciphertext }, N, E);
    return this.bigIntToBytes(message);
  }
  public sign(message: Uint8Array, n: Uint8Array, e: Uint8Array): Uint8Array {
    const m = this.bytesToBigInt(message);
    const N = this.bytesToBigInt(n);
    const E = this.bytesToBigInt(e);
    const signature = this.signbigint(m, N, E);
    return this.bigIntToBytes(signature, this.bigIntToBytes(N).length);
  }
  public verify(
    signature: Uint8Array,
    message: Uint8Array,
    n: Uint8Array,
    e: Uint8Array,
  ): boolean {
    const sig = this.bytesToBigInt(signature);
    const m = this.bytesToBigInt(message);
    const N = this.bytesToBigInt(n);
    const E = this.bytesToBigInt(e);
    return this.verifybigint(sig, m, N, E);
  }
}

async function main() {
  const rsa = new what_is_this();
  console.time("Key generation");
  const { n, e } = rsa.generateKey(2048);
  console.timeEnd("Key generation");

console.time("Encryption and decryption");
  const message = new TextEncoder().encode("Hello, RSA!");
  const a = rsa.encrypt(message, n, e);
  const decryptedMessage = rsa.decrypt(a, n, e);
  console.timeEnd("Encryption and decryption");
  console.time("Signing and verifying");
  const signature = rsa.sign(message, n, e);
  console.timeEnd("Signing and verifying");

  const isValid = rsa.verify(signature, message, n, e);
  console.time("Recovering p and q");
  const pq = rsa.keytopq(n, e);
  console.timeEnd("Recovering p and q");
}

main().catch(console.error);
