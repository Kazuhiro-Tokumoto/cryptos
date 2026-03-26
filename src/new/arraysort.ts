/**
 * Uint8Array専用の計数ソート (Counting Sort)
 */
/**
 * ホワイトスペース無視機能付き・高速計数ソート
 * JSONのインデントや改行に関わらず、中身のデータ成分のみで一意なバイナリを生成する。
 */
export function dylaCleanSort(
  input: ArrayBufferView | ArrayBuffer,
): Uint8Array {
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

// ===== 動作検証用テスト =====

console.log('Generating 100MB JSON...');
const count = 10000000;
const arr = [];
for (let i = 0; i < count; i++) {
  arr.push({ id: i, name: 'User' + i, email: 'user' + i + '@example.com', score: Math.random() });
}
const big = JSON.stringify({ users: arr });
console.log('Size:', (big.length / 1024 / 1024).toFixed(2), 'MB');

const buf = new Uint8Array(Buffer.from(big));

// dylaCleanSort
console.time('dylaCleanSort');
const res1 = dylaCleanSort(buf);
console.timeEnd('dylaCleanSort');

// 普通のsort
console.time('normalSort');
const sorted = [...buf].sort((a, b) => a - b);
const res2 = Buffer.from(sorted);
console.timeEnd('normalSort');

console.log('dylaCleanSort Length:', res1.length);
console.log('normalSort Length:', res2.length);