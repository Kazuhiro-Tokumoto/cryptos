function modExp(base, exp, mod) {
    if (mod === 1n)
        return 0n;
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
        // 指数が奇数の場合、現在のbaseを掛ける
        if (exp % 2n === 1n) {
            result = (result * base) % mod;
        }
        // 指数を半分にし、baseを2乗する（繰り返し二乗法）
        exp = exp / 2n;
        base = (base * base) % mod;
    }
    return result;
}
// 使い方例: 2^960 % 3080 を計算
const base = 17n;
const exp = 959n;
const mod = 3080n;
const result = modExp(base, exp, mod);
console.log(`modExp(${base}, ${exp}, ${mod}) = ${result}`);
console.log(17 * 1993 % 3080); // 17^959 % 3080 と同じ結果になるはず
const m = 99n;
console.log(modExp(m, 17n, 3233n)); // 17^959 % 99 を計算
console.log(modExp(modExp(m, 17n, 3233n), 1993n, 3233n)); // 17^959 % 99 を計算
export {};
