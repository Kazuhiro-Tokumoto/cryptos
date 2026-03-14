// jacobian.h
// P-256 ヤコビアン座標の点演算 + スカラー倍
// field256.h に依存

#ifndef JACOBIAN_H
#define JACOBIAN_H

#include "field256.h"

// =============================================
// ヤコビアン座標の点 [X:Y:Z]
// 無限遠点: Z = 0
// =============================================
typedef struct {
  fe256 X;
  fe256 Y;
  fe256 Z;
} jac_point;

// アフィン座標の点 (x, y)
typedef struct {
  fe256 x;
  fe256 y;
} aff_point;

// P-256 のパラメータ a = -3
// a = P - 3 = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
static const fe256 CURVE_A = {{
  0xFFFFFFFFFFFFFFFCULL,
  0x00000000FFFFFFFFULL,
  0x0000000000000000ULL,
  0xFFFFFFFF00000001ULL
}};

// ベースポイント G
static const aff_point CURVE_G = {
  {{ 0xF4A13945D898C296ULL, 0x77037D812DEB33A0ULL,
     0xF8BCE6E563A440F2ULL, 0x6B17D1F2E12C4247ULL }},
  {{ 0xCBB6406837BF51F5ULL, 0x2BCE33576B315ECEULL,
     0x8EE7EB4A7C0F9E16ULL, 0x4FE342E2FE1A7F9BULL }}
};

// 位数 N
static const fe256 CURVE_N = {{
  0xF3B9CAC2FC632551ULL,
  0xBCE6FAADA7179E84ULL,
  0xFFFFFFFFFFFFFFFFULL,
  0xFFFFFFFF00000000ULL
}};

// 無限遠点
static const jac_point JAC_INFINITY = {
  {{ 0, 0, 0, 0 }},
  {{ 1, 0, 0, 0 }},
  {{ 0, 0, 0, 0 }}
};

// fe256がゼロかチェック
static inline int fe256_is_zero(const fe256 *a) {
  return (a->v[0] | a->v[1] | a->v[2] | a->v[3]) == 0;
}

// fe256の等値チェック
static inline int fe256_eq(const fe256 *a, const fe256 *b) {
  return (a->v[0] == b->v[0]) && (a->v[1] == b->v[1]) &&
         (a->v[2] == b->v[2]) && (a->v[3] == b->v[3]);
}

// =============================================
// 点の2倍算: R = 2*P (ヤコビアン, a=-3 最適化)
// =============================================
static void jac_double(jac_point *R, const jac_point *P) {
  if (fe256_is_zero(&P->Z)) {
    *R = JAC_INFINITY;
    return;
  }

  fe256 YY, YYYY, ZZ, S, M, X3, Y3, Z3, tmp, tmp2;

  // YY = Y^2
  fe256_sqr(&YY, &P->Y);
  // YYYY = YY^2
  fe256_sqr(&YYYY, &YY);
  // ZZ = Z^2
  fe256_sqr(&ZZ, &P->Z);

  // S = 4 * X * YY
  fe256_mul(&S, &P->X, &YY);
  fe256_add(&S, &S, &S); // 2*X*YY
  fe256_add(&S, &S, &S); // 4*X*YY

  // M = 3*(X+ZZ)*(X-ZZ)  ... a=-3 の最適化
  fe256_add(&tmp, &P->X, &ZZ);   // X+ZZ
  fe256_sub(&tmp2, &P->X, &ZZ);  // X-ZZ
  fe256_mul(&M, &tmp, &tmp2);     // (X+ZZ)(X-ZZ)
  fe256_add(&tmp, &M, &M);        // 2*(...)
  fe256_add(&M, &tmp, &M);        // 3*(...)

  // X3 = M^2 - 2*S
  fe256_sqr(&X3, &M);
  fe256_sub(&X3, &X3, &S);
  fe256_sub(&X3, &X3, &S);

  // Y3 = M*(S - X3) - 8*YYYY
  fe256_sub(&tmp, &S, &X3);
  fe256_mul(&Y3, &M, &tmp);
  // 8*YYYY
  fe256_add(&tmp, &YYYY, &YYYY); // 2
  fe256_add(&tmp, &tmp, &tmp);   // 4
  fe256_add(&tmp, &tmp, &tmp);   // 8
  fe256_sub(&Y3, &Y3, &tmp);

  // Z3 = 2*Y*Z
  fe256_mul(&Z3, &P->Y, &P->Z);
  fe256_add(&Z3, &Z3, &Z3);

  R->X = X3;
  R->Y = Y3;
  R->Z = Z3;
}

// =============================================
// 点の加算: R = P + Q (ヤコビアン)
// =============================================
static void jac_add(jac_point *R, const jac_point *P, const jac_point *Q) {
  if (fe256_is_zero(&P->Z)) { *R = *Q; return; }
  if (fe256_is_zero(&Q->Z)) { *R = *P; return; }

  fe256 Z1Z1, Z2Z2, U1, U2, S1, S2, H, HH, HHH, rr, U1HH;
  fe256 X3, Y3, Z3, tmp;

  // Z1Z1 = Z1^2, Z2Z2 = Z2^2
  fe256_sqr(&Z1Z1, &P->Z);
  fe256_sqr(&Z2Z2, &Q->Z);

  // U1 = X1*Z2Z2, U2 = X2*Z1Z1
  fe256_mul(&U1, &P->X, &Z2Z2);
  fe256_mul(&U2, &Q->X, &Z1Z1);

  // S1 = Y1*Z2*Z2Z2, S2 = Y2*Z1*Z1Z1
  fe256_mul(&tmp, &Q->Z, &Z2Z2);
  fe256_mul(&S1, &P->Y, &tmp);
  fe256_mul(&tmp, &P->Z, &Z1Z1);
  fe256_mul(&S2, &Q->Y, &tmp);

  // H = U2 - U1
  fe256_sub(&H, &U2, &U1);
  // rr = S2 - S1
  fe256_sub(&rr, &S2, &S1);

  if (fe256_is_zero(&H)) {
    if (fe256_is_zero(&rr)) {
      jac_double(R, P);
      return;
    }
    *R = JAC_INFINITY;
    return;
  }

  // HH = H^2, HHH = H*HH
  fe256_sqr(&HH, &H);
  fe256_mul(&HHH, &H, &HH);

  // U1HH = U1*HH
  fe256_mul(&U1HH, &U1, &HH);

  // X3 = rr^2 - HHH - 2*U1HH
  fe256_sqr(&X3, &rr);
  fe256_sub(&X3, &X3, &HHH);
  fe256_sub(&X3, &X3, &U1HH);
  fe256_sub(&X3, &X3, &U1HH);

  // Y3 = rr*(U1HH - X3) - S1*HHH
  fe256_sub(&tmp, &U1HH, &X3);
  fe256_mul(&Y3, &rr, &tmp);
  fe256_mul(&tmp, &S1, &HHH);
  fe256_sub(&Y3, &Y3, &tmp);

  // Z3 = H*Z1*Z2
  fe256_mul(&tmp, &P->Z, &Q->Z);
  fe256_mul(&Z3, &H, &tmp);

  R->X = X3;
  R->Y = Y3;
  R->Z = Z3;
}

// =============================================
// ヤコビアン → アフィン変換
// =============================================
static void jac_to_affine(aff_point *R, const jac_point *P) {
  if (fe256_is_zero(&P->Z)) {
    R->x = FIELD_ZERO;
    R->y = FIELD_ZERO;
    return;
  }
  fe256 invZ, invZ2, invZ3;
  fe256_inv(&invZ, &P->Z);
  fe256_sqr(&invZ2, &invZ);
  fe256_mul(&invZ3, &invZ2, &invZ);
  fe256_mul(&R->x, &P->X, &invZ2);
  fe256_mul(&R->y, &P->Y, &invZ3);
}

// =============================================
// スカラー倍: R = k * P (ウィンドウ幅4)
// =============================================
static void scalar_mult(aff_point *R, const fe256 *k, const aff_point *P) {
  const int W = 4;
  const int TABLE_SIZE = 1 << W; // 16

  // 事前テーブル: table[i] = i*P (i=0..15)
  jac_point table[16];
  table[0] = JAC_INFINITY;
  table[1].X = P->x;
  table[1].Y = P->y;
  table[1].Z = FIELD_ONE;
  for (int i = 2; i < TABLE_SIZE; i++) {
    jac_add(&table[i], &table[i - 1], &table[1]);
  }

  jac_point acc = JAC_INFINITY;

  // 上位ビットから4bitずつ
  for (int i = 256 - W; i >= 0; i -= W) {
    // 4回ダブリング
    for (int j = 0; j < W; j++) {
      jac_double(&acc, &acc);
    }
    // ウィンドウ値
    int limb_idx = i / 64;
    int bit_idx = i % 64;
    int win = (int)((k->v[limb_idx] >> bit_idx) & 0xF);
    // 64bit境界をまたぐ場合
    if (bit_idx > 60 && limb_idx < 3) {
      win |= (int)(k->v[limb_idx + 1] << (64 - bit_idx)) & 0xF;
    }
    if (win > 0) {
      jac_add(&acc, &acc, &table[win]);
    }
  }

  jac_to_affine(R, &acc);
}

// =============================================
// G点専用スカラー倍 (事前計算テーブル)
// =============================================

// 事前計算テーブル: G_TABLE[i][j] = j * 2^(4i) * G  (i=0..63, j=0..15)
// 初期化は init_g_table() で1回だけ行う
static jac_point G_TABLE[64][16];
static int g_table_initialized = 0;

static void init_g_table(void) {
  if (g_table_initialized) return;

  jac_point base;
  base.X = CURVE_G.x;
  base.Y = CURVE_G.y;
  base.Z = FIELD_ONE;

  for (int i = 0; i < 64; i++) {
    G_TABLE[i][0] = JAC_INFINITY;
    G_TABLE[i][1] = base;
    for (int j = 2; j < 16; j++) {
      jac_add(&G_TABLE[i][j], &G_TABLE[i][j - 1], &base);
    }
    // base = 2^4 * base
    for (int j = 0; j < 4; j++) {
      jac_double(&base, &base);
    }
  }
  g_table_initialized = 1;
}

static void scalar_mult_g(aff_point *R, const fe256 *k) {
  init_g_table();

  jac_point acc = JAC_INFINITY;
  for (int i = 0; i < 64; i++) {
    int bit_pos = i * 4;
    int limb_idx = bit_pos / 64;
    int bit_idx = bit_pos % 64;
    int win = (int)((k->v[limb_idx] >> bit_idx) & 0xF);
    if (bit_idx > 60 && limb_idx < 3) {
      win |= (int)(k->v[limb_idx + 1] << (64 - bit_idx)) & 0xF;
    }
    if (win > 0) {
      jac_add(&acc, &acc, &G_TABLE[i][win]);
    }
  }
  jac_to_affine(R, &acc);
}

// =============================================
// wNAF Shamir's Trick (検証用)
// =============================================
static int wnaf_repr(int8_t *naf, const fe256 *k, int w) {
  // k を wNAF 表現に変換。返り値 = 長さ
  int half_w = 1 << (w - 1);
  int mask = (1 << w) - 1;

  // 作業用コピー (最大257bit必要)
  uint64_t tmp[5];
  memcpy(tmp, k->v, 32);
  tmp[4] = 0;

  int len = 0;
  while (tmp[0] || tmp[1] || tmp[2] || tmp[3] || tmp[4]) {
    if (tmp[0] & 1) {
      int val = (int)(tmp[0] & mask);
      if (val >= half_w) val -= (1 << w);
      naf[len] = (int8_t)val;
      // tmp -= val
      if (val > 0) {
        uint64_t borrow = (uint64_t)val;
        for (int i = 0; i < 5; i++) {
          if (tmp[i] >= borrow) { tmp[i] -= borrow; break; }
          tmp[i] -= borrow;
          borrow = 1;
        }
      } else {
        uint64_t carry = (uint64_t)(-val);
        for (int i = 0; i < 5; i++) {
          uint64_t sum = tmp[i] + carry;
          carry = (sum < tmp[i]) ? 1 : 0;
          tmp[i] = sum;
          if (!carry) break;
        }
      }
    } else {
      naf[len] = 0;
    }
    len++;
    // tmp >>= 1
    for (int i = 0; i < 4; i++) {
      tmp[i] = (tmp[i] >> 1) | (tmp[i + 1] << 63);
    }
    tmp[4] >>= 1;
  }
  return len;
}

static void shamirs_mult(aff_point *R,
                          const fe256 *k1, const aff_point *P1,
                          const fe256 *k2, const aff_point *P2) {
  const int W = 4;
  const int HALF_W = 1 << (W - 1); // 8

  // 奇数倍テーブル: tbl[i] = (2i+1)*P  (i=0..7)
  jac_point tbl1[8], tbl2[8];

  jac_point P1j = { P1->x, P1->y, FIELD_ONE };
  jac_point P2j = { P2->x, P2->y, FIELD_ONE };
  jac_point dbl1, dbl2;
  jac_double(&dbl1, &P1j);
  jac_double(&dbl2, &P2j);

  tbl1[0] = P1j;
  tbl2[0] = P2j;
  for (int i = 1; i < HALF_W; i++) {
    jac_add(&tbl1[i], &tbl1[i - 1], &dbl1);
    jac_add(&tbl2[i], &tbl2[i - 1], &dbl2);
  }

  // wNAF変換
  int8_t naf1[260], naf2[260];
  memset(naf1, 0, sizeof(naf1));
  memset(naf2, 0, sizeof(naf2));
  int len1 = wnaf_repr(naf1, k1, W);
  int len2 = wnaf_repr(naf2, k2, W);
  int max_len = len1 > len2 ? len1 : len2;

  jac_point acc = JAC_INFINITY;

  for (int i = max_len - 1; i >= 0; i--) {
    jac_double(&acc, &acc);

    if (naf1[i] > 0) {
      jac_add(&acc, &acc, &tbl1[(naf1[i] - 1) >> 1]);
    } else if (naf1[i] < 0) {
      jac_point neg = tbl1[(-naf1[i] - 1) >> 1];
      fe256 negY;
      fe256_sub(&negY, &FIELD_P, &neg.Y);
      neg.Y = negY;
      jac_add(&acc, &acc, &neg);
    }

    if (naf2[i] > 0) {
      jac_add(&acc, &acc, &tbl2[(naf2[i] - 1) >> 1]);
    } else if (naf2[i] < 0) {
      jac_point neg = tbl2[(-naf2[i] - 1) >> 1];
      fe256 negY;
      fe256_sub(&negY, &FIELD_P, &neg.Y);
      neg.Y = negY;
      jac_add(&acc, &acc, &neg);
    }
  }

  jac_to_affine(R, &acc);
}

#endif // JACOBIAN_H
