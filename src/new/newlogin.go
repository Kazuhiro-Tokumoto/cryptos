package main

import (
	"encoding/binary"
	"math/bits"
)

var sha256K = [64]uint32{
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
}

func sha256Hash(data []byte) [32]byte {
	h0 := uint32(0x6a09e667)
	h1 := uint32(0xbb67ae85)
	h2 := uint32(0x3c6ef372)
	h3 := uint32(0xa54ff53a)
	h4 := uint32(0x510e527f)
	h5 := uint32(0x9b05688c)
	h6 := uint32(0x1f83d9ab)
	h7 := uint32(0x5be0cd19)

	length := len(data)
	bitLen := uint64(length) * 8
	blockCount := (length+72)/64 + 1
	if (length+9)%64 == 0 {
		blockCount = (length + 9) / 64
	} else {
		blockCount = (length+9)/64 + 1
	}
	blocks := make([]byte, blockCount*64)
	copy(blocks, data)
	blocks[length] = 0x80
	binary.BigEndian.PutUint32(blocks[len(blocks)-8:], uint32(bitLen>>32))
	binary.BigEndian.PutUint32(blocks[len(blocks)-4:], uint32(bitLen))

	var W [64]uint32
	for i := 0; i < len(blocks); i += 64 {
		for t := 0; t < 16; t++ {
			W[t] = binary.BigEndian.Uint32(blocks[i+t*4:])
		}
		for t := 16; t < 64; t++ {
			s0 := bits.RotateLeft32(W[t-15], -7) ^ bits.RotateLeft32(W[t-15], -18) ^ (W[t-15] >> 3)
			s1 := bits.RotateLeft32(W[t-2], -17) ^ bits.RotateLeft32(W[t-2], -19) ^ (W[t-2] >> 10)
			W[t] = W[t-16] + s0 + W[t-7] + s1
		}

		a, b, c, d := h0, h1, h2, h3
		e, f, g, h := h4, h5, h6, h7

		for t := 0; t < 64; t++ {
			S1 := bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)
			ch := (e & f) ^ (^e & g)
			temp1 := h + S1 + ch + sha256K[t] + W[t]
			S0 := bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)
			maj := (a & b) ^ (a & c) ^ (b & c)
			temp2 := S0 + maj

			h = g
			g = f
			f = e
			e = d + temp1
			d = c
			c = b
			b = a
			a = temp1 + temp2
		}

		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e
		h5 += f
		h6 += g
		h7 += h
	}

	var result [32]byte
	binary.BigEndian.PutUint32(result[0:], h0)
	binary.BigEndian.PutUint32(result[4:], h1)
	binary.BigEndian.PutUint32(result[8:], h2)
	binary.BigEndian.PutUint32(result[12:], h3)
	binary.BigEndian.PutUint32(result[16:], h4)
	binary.BigEndian.PutUint32(result[20:], h5)
	binary.BigEndian.PutUint32(result[24:], h6)
	binary.BigEndian.PutUint32(result[28:], h7)
	return result
}

func stretch(iter int, data []byte) []byte {
	cur := data
	for i := 0; i < iter; i++ {
		h := sha256Hash(cur)
		cur = h[:]
	}
	return cur
}

func uint8ArrayPasswordStretch(iter int, password, salt []byte) []byte {
	combined := append(password, salt...)
	return stretch(iter, combined)
}

func passwordStretch(iter int, password, username string) []byte {
	passwordBytes := []byte(password)
	saltBytes := []byte(username)
	return uint8ArrayPasswordStretch(iter, passwordBytes, saltBytes)
}

func uint8ArrayToHex(a []byte) string {
	const hextable = "0123456789abcdef"
	dst := make([]byte, len(a)*2)
	for i, v := range a {
		dst[i*2] = hextable[v>>4]
		dst[i*2+1] = hextable[v&0x0f]
	}
	return string(dst)
}

func hexToBigInt(hex string) []byte {
	// 必要に応じてmath/big.Intで実装
	panic("use math/big.Int directly")
}

func uint8ArrayToBigInt(a []byte) string {
	return "0x" + uint8ArrayToHex(a)
}

func filterByBytes(text string) bool {
	ngBytes := map[byte]bool{0x0a: true, 0x0d: true, 0x20: true}
	for _, b := range []byte(text) {
		if ngBytes[b] {
			return false
		}
	}
	return true
}
