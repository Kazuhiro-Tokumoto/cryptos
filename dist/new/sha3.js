class sha3 {
    KECCAK_ROUNDS = 24;
    RC = [
        0x0000000000000001n,
        0x0000000000008082n,
        0x800000000000808an,
        0x8000000080008000n,
        0x000000000000808bn,
        0x0000000080000001n,
        0x8000000080008081n,
        0x8000000000008009n,
        0x000000000000008an,
        0x0000000000000088n,
        0x0000000080008009n,
        0x000000008000000an,
        0x000000008000808bn,
        0x800000000000008bn,
        0x8000000000008089n,
        0x8000000000008003n,
        0x8000000000008002n,
        0x8000000000000080n,
        0x000000000000800an,
        0x800000008000000an,
        0x8000000080008081n,
        0x8000000000008080n,
        0x0000000080000001n,
        0x8000000080008008n,
    ];
    ROT_OFFSETS = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    ];
    PI_LANES = [
        0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14,
        24, 9, 19, 4,
    ];
    MASK64 = 0xffffffffffffffffn;
    rotl64(x, n) {
        return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & this.MASK64;
    }
    keccakF1600(state) {
        const C = new Array(5);
        const D = new Array(5);
        const B = new Array(25);
        for (let round = 0; round < this.KECCAK_ROUNDS; round++) {
            // θ step
            for (let x = 0; x < 5; x++) {
                C[x] =
                    state[x] ^
                        state[x + 5] ^
                        state[x + 10] ^
                        state[x + 15] ^
                        state[x + 20];
            }
            for (let x = 0; x < 5; x++) {
                D[x] = C[(x + 4) % 5] ^ this.rotl64(C[(x + 1) % 5], 1);
                for (let y = 0; y < 25; y += 5) {
                    state[y + x] = (state[y + x] ^ D[x]) & this.MASK64;
                }
            }
            // ρ + π steps
            for (let i = 0; i < 25; i++) {
                B[this.PI_LANES[i]] = this.rotl64(state[i], this.ROT_OFFSETS[i]);
            }
            // χ step
            for (let y = 0; y < 25; y += 5) {
                for (let x = 0; x < 5; x++) {
                    state[y + x] =
                        (B[y + x] ^
                            (~B[y + ((x + 1) % 5)] & this.MASK64 & B[y + ((x + 2) % 5)])) &
                            this.MASK64;
                }
            }
            // ι step
            state[0] = (state[0] ^ this.RC[round]) & this.MASK64;
        }
    }
    keccakAbsorb(state, rateBytes, input, dsByte) {
        const rateLanes = rateBytes >> 3;
        let offset = 0;
        // Absorb full blocks
        while (offset + rateBytes <= input.length) {
            for (let i = 0; i < rateLanes; i++) {
                let lane = 0n;
                const base = offset + i * 8;
                for (let b = 0; b < 8; b++) {
                    lane |= BigInt(input[base + b]) << BigInt(b * 8);
                }
                state[i] = (state[i] ^ lane) & this.MASK64;
            }
            this.keccakF1600(state);
            offset += rateBytes;
        }
        // Padding
        const remaining = input.length - offset;
        const padded = new Uint8Array(rateBytes);
        padded.set(input.subarray(offset, offset + remaining));
        padded[remaining] = dsByte;
        padded[rateBytes - 1] |= 0x80;
        for (let i = 0; i < rateLanes; i++) {
            let lane = 0n;
            const base = i * 8;
            for (let b = 0; b < 8; b++) {
                lane |= BigInt(padded[base + b]) << BigInt(b * 8);
            }
            state[i] = (state[i] ^ lane) & this.MASK64;
        }
        this.keccakF1600(state);
    }
    keccakSqueeze(state, rateBytes, outLen) {
        const out = new Uint8Array(outLen);
        let offset = 0;
        const rateLanes = rateBytes >> 3;
        while (offset < outLen) {
            const blockLen = Math.min(rateBytes, outLen - offset);
            for (let i = 0; i < rateLanes && offset < outLen; i++) {
                const lane = state[i];
                for (let b = 0; b < 8 && offset < outLen; b++) {
                    out[offset++] = Number((lane >> BigInt(b * 8)) & 0xffn);
                }
            }
            if (offset < outLen) {
                this.keccakF1600(state);
            }
        }
        return out;
    }
    shake128(input, outLen) {
        const state = new Array(25).fill(0n);
        const rate = 168; // (1600 - 256) / 8
        this.keccakAbsorb(state, rate, input, 0x1f);
        return this.keccakSqueeze(state, rate, outLen);
    }
    shake256(input, outLen) {
        const state = new Array(25).fill(0n);
        const rate = 136; // (1600 - 512) / 8
        this.keccakAbsorb(state, rate, input, 0x1f);
        return this.keccakSqueeze(state, rate, outLen);
    }
}
const sha = new sha3();
const encoder = new TextEncoder();
const non = encoder.encode("");
function toHex(bytes) {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}
console.log(toHex(sha.shake128(non, 32)));
export {};
