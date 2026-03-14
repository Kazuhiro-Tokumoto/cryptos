// main.c
// コンパイル:
//   emcc main.c -O3 -o ecdsa_wasm.js \
//     -s EXPORTED_FUNCTIONS='["_ec_init","_ec_sign","_ec_verify","_ec_generate_keypair","_ec_privkey_to_pubkey","_ec_get_buf","_ec_buf_size","_malloc","_free"]' \
//     -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap"]' \
//     -s MODULARIZE=1 \
//     -s EXPORT_NAME=ECModule \
//     -s ALLOW_MEMORY_GROWTH=1

#include <emscripten.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "field256.h"
#include "jacobian.h"
#include "sha256.h"

// =============================================
// グローバル出力バッファ
// JS 側は ec_get_buf() でポインタを得て
// WebAssembly.Memory 経由で読み出す
// =============================================
#define OUT_BUF_SIZE 256
static uint8_t g_outbuf[OUT_BUF_SIZE];

EMSCRIPTEN_KEEPALIVE
uint8_t *ec_get_buf(void) { return g_outbuf; }

EMSCRIPTEN_KEEPALIVE
uint32_t ec_buf_size(void) { return OUT_BUF_SIZE; }

// =============================================
// ビッグエンディアン <-> fe256 変換
// =============================================
static void bytes_to_fe256(fe256 *r, const uint8_t *bytes) {
  for (int limb = 0; limb < 4; limb++) {
    const uint8_t *p = bytes + (3 - limb) * 8;
    r->v[limb] = ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48)
               | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32)
               | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16)
               | ((uint64_t)p[6] <<  8) |  (uint64_t)p[7];
  }
}

static void fe256_to_bytes(uint8_t *bytes, const fe256 *a) {
  for (int limb = 0; limb < 4; limb++) {
    uint8_t *p = bytes + (3 - limb) * 8;
    uint64_t v = a->v[limb];
    p[0]=(uint8_t)(v>>56); p[1]=(uint8_t)(v>>48);
    p[2]=(uint8_t)(v>>40); p[3]=(uint8_t)(v>>32);
    p[4]=(uint8_t)(v>>24); p[5]=(uint8_t)(v>>16);
    p[6]=(uint8_t)(v>> 8); p[7]=(uint8_t)(v);
  }
}

// =============================================
// fe256 の mod N 演算
// =============================================
static void fe256_add_mod_n(fe256 *r, const fe256 *a, const fe256 *b) {
  uint64_t carry = 0;
  for (int i = 0; i < 4; i++) {
    uint64_t s = a->v[i] + b->v[i];
    uint64_t c1 = (s < a->v[i]) ? 1ULL : 0ULL;
    uint64_t s2 = s + carry;
    uint64_t c2 = (s2 < s) ? 1ULL : 0ULL;
    r->v[i] = s2;
    carry = c1 + c2;
  }
  if (carry || fe256_gte(r, &CURVE_N)) {
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
      uint64_t ai = r->v[i], bi = CURVE_N.v[i];
      uint64_t d  = ai - bi;
      uint64_t b1 = (ai < bi) ? 1ULL : 0ULL;
      uint64_t d2 = d - borrow;
      uint64_t b2 = (d < borrow) ? 1ULL : 0ULL;
      r->v[i] = d2;
      borrow = b1 + b2;
    }
  }
}

// =============================================
// 曲線上の点か確認
// =============================================
static const fe256 CURVE_B_CORRECT = {{
  0x3BCE3C3E27D2604BULL,
  0x651D06B0CC53B0F6ULL,
  0xB3EBBD55769886BCULL,
  0x5AC635D8AA3A93E7ULL
}};

static int is_point_on_curve(const fe256 *x, const fe256 *y) {
  if (fe256_is_zero(x) && fe256_is_zero(y)) return 0;
  fe256 x2, x3, three_x, rhs, lhs;
  fe256_sqr(&x2, x);
  fe256_mul(&x3, &x2, x);
  fe256_add(&three_x, x, x);
  fe256_add(&three_x, &three_x, x);
  fe256_sub(&rhs, &x3, &three_x);
  fe256_add(&rhs, &rhs, &CURVE_B_CORRECT);
  fe256_sqr(&lhs, y);
  return fe256_eq(&lhs, &rhs);
}

// =============================================
// RFC 6979: 決定論的 k 生成
// =============================================
static void generate_k(fe256 *k_out,
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t *privkey) {
  uint8_t h1[32];
  sha256(msg, msg_len, h1);

  uint8_t V[32], K[32];
  memset(V, 0x01, 32);
  memset(K, 0x00, 32);

  uint8_t buf[97];
  memcpy(buf,    V,       32); buf[32] = 0x00;
  memcpy(buf+33, privkey, 32); memcpy(buf+65, h1, 32);
  hmac_sha256(K, 32, buf, 97, K);
  hmac_sha256(K, 32, V,  32, V);

  memcpy(buf,    V,       32); buf[32] = 0x01;
  memcpy(buf+33, privkey, 32); memcpy(buf+65, h1, 32);
  hmac_sha256(K, 32, buf, 97, K);
  hmac_sha256(K, 32, V,  32, V);

  for (;;) {
    hmac_sha256(K, 32, V, 32, V);
    bytes_to_fe256(k_out, V);
    int nonzero = (k_out->v[0]|k_out->v[1]|k_out->v[2]|k_out->v[3]) != 0;
    if (nonzero && !fe256_gte(k_out, &CURVE_N)) return;
    uint8_t buf2[33];
    memcpy(buf2, V, 32); buf2[32] = 0x00;
    hmac_sha256(K, 32, buf2, 33, K);
    hmac_sha256(K, 32, V,   32, V);
  }
}

// =============================================
// 初期化
// =============================================
EMSCRIPTEN_KEEPALIVE
void ec_init(void) { init_g_table(); }

// =============================================
// 鍵ペア生成
// 入力:  rand32     → 32B (ccall array)
// 出力:  g_outbuf   → privkey(32B) + pubX(32B) + pubY(32B) = 96B
// =============================================
EMSCRIPTEN_KEEPALIVE
void ec_generate_keypair(const uint8_t *rand32) {
  fe256 priv;
  bytes_to_fe256(&priv, rand32);
  aff_point pub;
  scalar_mult_g(&pub, &priv);
  memcpy(g_outbuf,    rand32, 32);          // privkey
  fe256_to_bytes(g_outbuf + 32, &pub.x);   // pubX
  fe256_to_bytes(g_outbuf + 64, &pub.y);   // pubY
}

// =============================================
// 秘密鍵 → 公開鍵
// 入力:  privkey    → 32B (ccall array)
// 出力:  g_outbuf   → pubX(32B) + pubY(32B) = 64B
// =============================================
EMSCRIPTEN_KEEPALIVE
void ec_privkey_to_pubkey(const uint8_t *privkey) {
  fe256 priv;
  bytes_to_fe256(&priv, privkey);
  aff_point pub;
  scalar_mult_g(&pub, &priv);
  fe256_to_bytes(g_outbuf,      &pub.x);
  fe256_to_bytes(g_outbuf + 32, &pub.y);
}

// =============================================
// 署名
// 入力:  msg        → 任意長 (ccall array)
//        msg_len    → メッセージ長
//        privkey    → 32B (ccall array)
// 出力:  g_outbuf   → Rx(32B) + Ry(32B) + s(32B) = 96B
// =============================================
EMSCRIPTEN_KEEPALIVE
void ec_sign(const uint8_t *msg, uint32_t msg_len, const uint8_t *privkey) {
  fe256 priv, k, s, e_fe;
  bytes_to_fe256(&priv, privkey);
  generate_k(&k, msg, (size_t)msg_len, privkey);

  aff_point R;
  scalar_mult_g(&R, &k);

  uint8_t Rx[32], Ry[32];
  fe256_to_bytes(Rx, &R.x);
  fe256_to_bytes(Ry, &R.y);

  uint8_t msg_be[32] = {0};
  if (msg_len <= 32) memcpy(msg_be + 32 - msg_len, msg, msg_len);
  else               memcpy(msg_be, msg + msg_len - 32, 32);

  uint8_t hash_input[96];
  memcpy(hash_input,    Rx,     32);
  memcpy(hash_input+32, Ry,     32);
  memcpy(hash_input+64, msg_be, 32);
  uint8_t e_hash[32];
  sha256(hash_input, 96, e_hash);

  bytes_to_fe256(&e_fe, e_hash);
  if (fe256_gte(&e_fe, &CURVE_N)) fe256_sub(&e_fe, &e_fe, &CURVE_N);

  fe256_add_mod_n(&s, &k, &priv);
  fe256_add_mod_n(&s, &s, &e_fe);

  memcpy(g_outbuf,    Rx, 32);
  memcpy(g_outbuf+32, Ry, 32);
  fe256_to_bytes(g_outbuf+64, &s);
}

// =============================================
// 検証
// 入力:  msg        → 任意長 (ccall array)
//        msg_len    → メッセージ長
//        pubkey     → 64B (ccall array: pubX+pubY)
//        sig        → 96B (ccall array: Rx+Ry+s)
// 返値:  1=valid, 0=invalid
// =============================================
EMSCRIPTEN_KEEPALIVE
int ec_verify(const uint8_t *msg, uint32_t msg_len,
              const uint8_t *pubkey, const uint8_t *sig) {
  fe256 Rx_fe, Ry_fe, px_fe, py_fe, s_fe, e_fe;
  bytes_to_fe256(&Rx_fe, sig);
  bytes_to_fe256(&Ry_fe, sig+32);
  bytes_to_fe256(&s_fe,  sig+64);
  bytes_to_fe256(&px_fe, pubkey);
  bytes_to_fe256(&py_fe, pubkey+32);

  if (!is_point_on_curve(&px_fe, &py_fe)) return 0;
  if (!is_point_on_curve(&Rx_fe, &Ry_fe)) return 0;

  uint8_t msg_be[32] = {0};
  if (msg_len <= 32) memcpy(msg_be + 32 - msg_len, msg, msg_len);
  else               memcpy(msg_be, msg + msg_len - 32, 32);

  uint8_t hash_input[96];
  memcpy(hash_input,    sig,    32);
  memcpy(hash_input+32, sig+32, 32);
  memcpy(hash_input+64, msg_be, 32);
  uint8_t e_hash[32];
  sha256(hash_input, 96, e_hash);

  bytes_to_fe256(&e_fe, e_hash);
  if (fe256_gte(&e_fe, &CURVE_N)) fe256_sub(&e_fe, &e_fe, &CURVE_N);

  aff_point left_aff, eG_aff;
  scalar_mult_g(&left_aff, &s_fe);
  scalar_mult_g(&eG_aff,   &e_fe);

  jac_point Rj   = { Rx_fe, Ry_fe, FIELD_ONE };
  jac_point Pubj = { px_fe, py_fe, FIELD_ONE };
  jac_point eGj  = { eG_aff.x, eG_aff.y, FIELD_ONE };
  jac_point left_j = { left_aff.x, left_aff.y, FIELD_ONE };

  jac_point right_j;
  jac_add(&right_j, &Rj,     &Pubj);
  jac_add(&right_j, &right_j, &eGj);

  fe256 Z1sq, Z2sq, Z1cu, Z2cu, lX, rX, lY, rY;
  fe256_sqr(&Z1sq, &left_j.Z);
  fe256_sqr(&Z2sq, &right_j.Z);
  fe256_mul(&Z1cu, &Z1sq, &left_j.Z);
  fe256_mul(&Z2cu, &Z2sq, &right_j.Z);
  fe256_mul(&lX, &left_j.X,  &Z2sq);
  fe256_mul(&rX, &right_j.X, &Z1sq);
  fe256_mul(&lY, &left_j.Y,  &Z2cu);
  fe256_mul(&rY, &right_j.Y, &Z1cu);

  return fe256_eq(&lX, &rX) && fe256_eq(&lY, &rY);
}