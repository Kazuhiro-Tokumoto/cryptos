function modExp(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 0n) throw new Error("Modulus cannot be zero.");
  if (exp < 0n) throw new Error("Exponent cannot be negative.");

  // mod が奇数でない場合は通常の実装にフォールバック
  if (!(mod & 1n)) {
    base = ((base % mod) + mod) % mod;
    let result = 1n;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % mod;
      exp >>= 1n;
      base = (base * base) % mod;
    }
    return result;
  }

  // Montgomery のビット長を計算
  const r = 1n << BigInt(mod.toString(2).length);  // R = 2^k > mod
  const rMask = r - 1n;

  // モンゴメリ逆元: mod * modInv ≡ -1 (mod R)
  function modInverse(a: bigint, m: bigint): bigint {
    let [old_r, r2] = [a, m];
    let [old_s, s] = [1n, 0n];
    while (r2 !== 0n) {
      const q = old_r / r2;
      [old_r, r2] = [r2, old_r - q * r2];
      [old_s, s] = [s, old_s - q * s];
    }
    return ((old_s % m) + m) % m;
  }

  const modInv = modInverse(mod, r);  // mod^{-1} mod R
  const rSq = (r * r) % mod;          // R^2 mod N (変換用)

  // モンゴメリリダクション: T * R^{-1} mod N
  function montReduce(t: bigint): bigint {
    const m = ((t & rMask) * modInv) & rMask;
    const u = (t + m * mod) >> BigInt(r.toString(2).length - 1);
    return u >= mod ? u - mod : u;
  }

  // モンゴメリ空間に変換
  base = ((base % mod) + mod) % mod;
  let a = montReduce(base * rSq);   // base * R mod N
  let result = montReduce(rSq);     // 1 * R mod N

  while (exp > 0n) {
    if (exp & 1n) result = montReduce(result * a);
    exp >>= 1n;
    a = montReduce(a * a);
  }

  // モンゴメリ空間から戻す
  return montReduce(result);
}

// 使い方例: 2^960 % 3080 を計算
const base = 2n;
const exp = 81083750464n;
const mod = 1000000n;
const result = modExp(base, exp, mod);
console.log(result)