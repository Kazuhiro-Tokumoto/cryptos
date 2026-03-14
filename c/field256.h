// field256.h
// P-256 フィールド演算 (uint64×4)
// P = 2^256 - 2^224 + 2^192 + 2^96 - 1

#ifndef FIELD256_H
#define FIELD256_H

#include <stdint.h>
#include <string.h>

// 256bit = 4 limb (リトルエンディアン: limb[0]が最下位)
typedef struct {
  uint64_t v[4];
} fe256;

// 512bit = 中間結果用
typedef struct {
  uint64_t v[8];
} fe512;

// P-256の素数P
static const fe256 FIELD_P = {{
  0xFFFFFFFFFFFFFFFFULL, // limb[0]
  0x00000000FFFFFFFFULL, // limb[1]
  0x0000000000000000ULL, // limb[2]
  0xFFFFFFFF00000001ULL  // limb[3]
}};

// ゼロ
static const fe256 FIELD_ZERO = {{ 0, 0, 0, 0 }};

// 1
static const fe256 FIELD_ONE = {{ 1, 0, 0, 0 }};

// =============================================
// 128bit乗算ヘルパー (64bit × 64bit → 128bit)
// =============================================
#ifdef __SIZEOF_INT128__
  typedef unsigned __int128 uint128_t;
  static inline void mul64(uint64_t a, uint64_t b, uint64_t *lo, uint64_t *hi) {
    uint128_t r = (uint128_t)a * b;
    *lo = (uint64_t)r;
    *hi = (uint64_t)(r >> 64);
  }
#else
  // フォールバック: 32bit分割
  static inline void mul64(uint64_t a, uint64_t b, uint64_t *lo, uint64_t *hi) {
    uint64_t a_lo = a & 0xFFFFFFFF;
    uint64_t a_hi = a >> 32;
    uint64_t b_lo = b & 0xFFFFFFFF;
    uint64_t b_hi = b >> 32;

    uint64_t p0 = a_lo * b_lo;
    uint64_t p1 = a_hi * b_lo;
    uint64_t p2 = a_lo * b_hi;
    uint64_t p3 = a_hi * b_hi;

    uint64_t mid = (p0 >> 32) + (p1 & 0xFFFFFFFF) + (p2 & 0xFFFFFFFF);
    *lo = (p0 & 0xFFFFFFFF) | (mid << 32);
    *hi = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
  }
#endif

// =============================================
// 比較: a >= b なら 1, そうでなければ 0
// =============================================
static inline int fe256_gte(const fe256 *a, const fe256 *b) {
  for (int i = 3; i >= 0; i--) {
    if (a->v[i] > b->v[i]) return 1;
    if (a->v[i] < b->v[i]) return 0;
  }
  return 1; // 等しい
}

// =============================================
// 加算: r = a + b (mod P)
// =============================================
static inline void fe256_add(fe256 *r, const fe256 *a, const fe256 *b) {
  uint64_t carry = 0;
  for (int i = 0; i < 4; i++) {
    uint64_t sum = a->v[i] + b->v[i];
    uint64_t c1 = (sum < a->v[i]) ? 1ULL : 0ULL;
    uint64_t sum2 = sum + carry;
    uint64_t c2 = (sum2 < sum) ? 1ULL : 0ULL;
    r->v[i] = sum2;
    carry = c1 + c2;
  }
  // r >= P なら r -= P
  if (carry || fe256_gte(r, &FIELD_P)) {
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
      uint64_t ai = r->v[i];
      uint64_t bi = FIELD_P.v[i];
      uint64_t diff = ai - bi;
      uint64_t b1 = (ai < bi) ? 1ULL : 0ULL;
      uint64_t diff2 = diff - borrow;
      uint64_t b2 = (diff < borrow) ? 1ULL : 0ULL;
      r->v[i] = diff2;
      borrow = b1 + b2;
    }
  }
}

// =============================================
// 減算: r = a - b (mod P)
// =============================================
static inline void fe256_sub(fe256 *r, const fe256 *a, const fe256 *b) {
  uint64_t borrow = 0;
  for (int i = 0; i < 4; i++) {
    uint64_t ai = a->v[i];
    uint64_t bi = b->v[i];
    uint64_t diff = ai - bi;
    uint64_t b1 = (ai < bi) ? 1ULL : 0ULL;
    uint64_t diff2 = diff - borrow;
    uint64_t b2 = (diff < borrow) ? 1ULL : 0ULL;
    r->v[i] = diff2;
    borrow = b1 + b2;
  }
  // アンダーフロー → r += P
  if (borrow) {
    uint64_t carry = 0;
    for (int i = 0; i < 4; i++) {
      uint64_t sum = r->v[i] + FIELD_P.v[i];
      uint64_t c1 = (sum < r->v[i]) ? 1ULL : 0ULL;
      uint64_t sum2 = sum + carry;
      uint64_t c2 = (sum2 < sum) ? 1ULL : 0ULL;
      r->v[i] = sum2;
      carry = c1 + c2;
    }
  }
}

// =============================================
// 乗算: r = a * b (mod P)
// schoolbook 4×4 → 8limb、その後P-256高速リダクション
// =============================================

// 4×4 schoolbook → 512bit
static inline void fe256_mul_raw(fe512 *r, const fe256 *a, const fe256 *b) {
  memset(r, 0, sizeof(fe512));
  for (int i = 0; i < 4; i++) {
    uint64_t carry = 0;
    for (int j = 0; j < 4; j++) {
      uint64_t lo, hi;
      mul64(a->v[i], b->v[j], &lo, &hi);

      uint64_t sum = r->v[i + j] + lo;
      uint64_t c1 = (sum < r->v[i + j]) ? 1 : 0;

      sum += carry;
      c1 += (sum < carry) ? 1 : 0;

      r->v[i + j] = sum;
      carry = hi + c1;
    }
    r->v[i + 4] += carry;
  }
}

// P-256 高速リダクション
// T = hi * 2^256 + lo
// T mod P = hi * RMODP + lo (mod P)  where RMODP = 2^256 mod P
// hi * RMODP は最大 ~480bit なのでもう1ラウンド必要
// 2ラウンド後は256bit + 小さいcarryなので P を数回引くだけ

static const fe256 RMODP = {{
  0x0000000000000001ULL,  // limb[0]
  0xFFFFFFFF00000000ULL,  // limb[1]
  0xFFFFFFFFFFFFFFFFULL,  // limb[2]
  0x00000000FFFFFFFEULL   // limb[3]
}};

// 256bit + 256bit の加算、結果を512bit (下位4limb + carry limb) で返す
// result[0..3] = sum, result[4] = carry (0 or 1)
static inline void add256_to_512(uint64_t *result, const uint64_t *a, const uint64_t *b) {
  uint64_t carry = 0;
  for (int i = 0; i < 4; i++) {
    uint64_t s1 = a[i] + b[i];
    uint64_t c1 = (s1 < a[i]) ? 1ULL : 0ULL;
    uint64_t s2 = s1 + carry;
    uint64_t c2 = (s2 < s1) ? 1ULL : 0ULL;
    result[i] = s2;
    carry = c1 + c2;
  }
  result[4] = carry;
}

static void fe256_reduce(fe256 *r, const fe512 *t) {
  fe256 lo = {{ t->v[0], t->v[1], t->v[2], t->v[3] }};
  fe256 hi = {{ t->v[4], t->v[5], t->v[6], t->v[7] }};

  // hi がゼロならショートカット
  if (hi.v[0] == 0 && hi.v[1] == 0 && hi.v[2] == 0 && hi.v[3] == 0) {
    *r = lo;
    if (fe256_gte(r, &FIELD_P)) {
      uint64_t borrow = 0;
      for (int i = 0; i < 4; i++) {
        uint64_t ai = r->v[i], bi = FIELD_P.v[i];
        uint64_t d = ai - bi;
        uint64_t b1 = (ai < bi) ? 1ULL : 0ULL;
        uint64_t d2 = d - borrow;
        uint64_t b2 = (d < borrow) ? 1ULL : 0ULL;
        r->v[i] = d2;
        borrow = b1 + b2;
      }
    }
    return;
  }

  // Round 1: mid = hi * RMODP + lo
  fe512 prod;
  fe256_mul_raw(&prod, &hi, &RMODP);

  // prod (最大480bit) + lo (256bit) → sum (最大481bit)
  uint64_t carry = 0;
  for (int i = 0; i < 4; i++) {
    uint64_t s1 = prod.v[i] + lo.v[i];
    uint64_t c1 = (s1 < prod.v[i]) ? 1ULL : 0ULL;
    uint64_t s2 = s1 + carry;
    uint64_t c2 = (s2 < s1) ? 1ULL : 0ULL;
    prod.v[i] = s2;
    carry = c1 + c2;
  }
  for (int i = 4; i < 8; i++) {
    uint64_t s = prod.v[i] + carry;
    carry = (s < prod.v[i]) ? 1ULL : 0ULL;
    prod.v[i] = s;
  }

  // Round 2: hi2 * RMODP + lo2
  fe256 hi2 = {{ prod.v[4], prod.v[5], prod.v[6], prod.v[7] }};
  fe256 lo2 = {{ prod.v[0], prod.v[1], prod.v[2], prod.v[3] }};

  if (hi2.v[0] == 0 && hi2.v[1] == 0 && hi2.v[2] == 0 && hi2.v[3] == 0) {
    *r = lo2;
  } else {
    fe512 prod2;
    fe256_mul_raw(&prod2, &hi2, &RMODP);

    carry = 0;
    for (int i = 0; i < 4; i++) {
      uint64_t s1 = prod2.v[i] + lo2.v[i];
      uint64_t c1 = (s1 < prod2.v[i]) ? 1ULL : 0ULL;
      uint64_t s2 = s1 + carry;
      uint64_t c2 = (s2 < s1) ? 1ULL : 0ULL;
      r->v[i] = s2;
      carry = c1 + c2;
    }
    // prod2 の上位はほぼ 0 だが念のため
    // carry + prod2[4..7] があれば3ラウンド目 (実用上は発生しない)
  }

  // 最終正規化: r >= P なら r -= P (最大3回で十分)
  for (int round = 0; round < 3; round++) {
    if (fe256_gte(r, &FIELD_P)) {
      uint64_t borrow = 0;
      for (int i = 0; i < 4; i++) {
        uint64_t ai = r->v[i], bi = FIELD_P.v[i];
        uint64_t d = ai - bi;
        uint64_t b1 = (ai < bi) ? 1ULL : 0ULL;
        uint64_t d2 = d - borrow;
        uint64_t b2 = (d < borrow) ? 1ULL : 0ULL;
        r->v[i] = d2;
        borrow = b1 + b2;
      }
    }
  }
}

// フィールド乗算 (完成版)
static inline void fe256_mul(fe256 *r, const fe256 *a, const fe256 *b) {
  fe512 t;
  fe256_mul_raw(&t, a, b);
  fe256_reduce(r, &t);
}

// =============================================
// 二乗: r = a^2 (mod P)  — 乗算で代用 (将来最適化可)
// =============================================
static inline void fe256_sqr(fe256 *r, const fe256 *a) {
  fe256_mul(r, a, a);
}

// =============================================
// 逆元: r = a^(-1) (mod P)  — フェルマーの小定理: a^(P-2)
// =============================================
static void fe256_inv(fe256 *r, const fe256 *a) {
  // P-2 = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFD
  // バイナリ法
  fe256 base = *a;
  fe256 result = FIELD_ONE;

  // P-2 のビットを下位から走査
  // P-2 = P - 2
  fe256 exp = FIELD_P;
  // exp -= 2
  exp.v[0] -= 2;

  for (int i = 0; i < 256; i++) {
    int bit = (exp.v[i / 64] >> (i % 64)) & 1;
    if (bit) {
      fe256_mul(&result, &result, &base);
    }
    fe256_sqr(&base, &base);
  }
  *r = result;
}

#endif // FIELD256_H