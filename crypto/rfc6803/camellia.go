package rfc6803

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math/bits"
)

const camelliaBlockSize = 16

// camelliaCipher implements cipher.Block for the Camellia block cipher (RFC 3713).
type camelliaCipher struct {
	kw [4]uint64
	k  [24]uint64
	ke [6]uint64

	rounds int // 18 for 128-bit, 24 for 256-bit
}

// NewCamelliaCipher creates a new Camellia cipher with the given key.
// Supported key sizes: 16 bytes (128-bit), 32 bytes (256-bit).
func NewCamelliaCipher(key []byte) (cipher.Block, error) {
	switch len(key) {
	case 16:
		return newCamellia128(key)
	case 32:
		return newCamellia256(key)
	default:
		return nil, fmt.Errorf("camellia: invalid key size %d", len(key))
	}
}

// Sigma constants from RFC 3713.
const (
	sigma1 = 0xA09E667F3BCC908B
	sigma2 = 0xB67AE8584CAA73B2
	sigma3 = 0xC6EF372FE94F82BE
	sigma4 = 0x54FF53A5F1D36F1C
	sigma5 = 0x10E527FADE682D1D
	sigma6 = 0xB05688C2B3E6C1FD
)

// SBOX1 from RFC 3713 Appendix A.
var sbox1 = [256]byte{
	112, 130, 44, 236, 179, 39, 192, 229, 228, 133, 87, 53, 234, 12, 174, 65,
	35, 239, 107, 147, 69, 25, 165, 33, 237, 14, 79, 78, 29, 101, 146, 189,
	134, 184, 175, 143, 124, 235, 31, 206, 62, 48, 220, 95, 94, 197, 11, 26,
	166, 225, 57, 202, 213, 71, 93, 61, 217, 1, 90, 214, 81, 86, 108, 77,
	139, 13, 154, 102, 251, 204, 176, 45, 116, 18, 43, 32, 240, 177, 132, 153,
	223, 76, 203, 194, 52, 126, 118, 5, 109, 183, 169, 49, 209, 23, 4, 215,
	20, 88, 58, 97, 222, 27, 17, 28, 50, 15, 156, 22, 83, 24, 242, 34,
	254, 68, 207, 178, 195, 181, 122, 145, 36, 8, 232, 168, 96, 252, 105, 80,
	170, 208, 160, 125, 161, 137, 98, 151, 84, 91, 30, 149, 224, 255, 100, 210,
	16, 196, 0, 72, 163, 247, 117, 219, 138, 3, 230, 218, 9, 63, 221, 148,
	135, 92, 131, 2, 205, 74, 144, 51, 115, 103, 246, 243, 157, 127, 191, 226,
	82, 155, 216, 38, 200, 55, 198, 59, 129, 150, 111, 75, 19, 190, 99, 46,
	233, 121, 167, 140, 159, 110, 188, 142, 41, 245, 249, 182, 47, 253, 180, 89,
	120, 152, 6, 106, 231, 70, 113, 186, 212, 37, 171, 66, 136, 162, 141, 250,
	114, 7, 185, 85, 248, 238, 172, 10, 54, 73, 42, 104, 60, 56, 241, 164,
	64, 40, 211, 123, 187, 201, 67, 193, 21, 227, 173, 244, 119, 199, 128, 158,
}

func rotl8(x byte, n uint) byte {
	return (x << n) | (x >> (8 - n))
}

func fFunc(input, ke uint64) uint64 {
	x := input ^ ke

	t1 := sbox1[byte(x>>56)]
	t2 := rotl8(sbox1[byte(x>>48)], 1) // SBOX2
	t3 := rotl8(sbox1[byte(x>>40)], 7) // SBOX3
	t4 := sbox1[rotl8(byte(x>>32), 1)] // SBOX4
	t5 := rotl8(sbox1[byte(x>>24)], 1) // SBOX2
	t6 := rotl8(sbox1[byte(x>>16)], 7) // SBOX3
	t7 := sbox1[rotl8(byte(x>>8), 1)]  // SBOX4
	t8 := sbox1[byte(x)]

	// P-function from RFC 3713.
	y1 := t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8
	y2 := t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8
	y3 := t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8
	y4 := t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7
	y5 := t1 ^ t2 ^ t6 ^ t7 ^ t8
	y6 := t2 ^ t3 ^ t5 ^ t7 ^ t8
	y7 := t3 ^ t4 ^ t5 ^ t6 ^ t8
	y8 := t1 ^ t4 ^ t5 ^ t6 ^ t7

	return uint64(y1)<<56 | uint64(y2)<<48 | uint64(y3)<<40 | uint64(y4)<<32 |
		uint64(y5)<<24 | uint64(y6)<<16 | uint64(y7)<<8 | uint64(y8)
}

func fl(x, k uint64) uint64 {
	x1 := uint32(x >> 32)
	x2 := uint32(x)
	k1 := uint32(k >> 32)
	k2 := uint32(k)

	x2 = x2 ^ bits.RotateLeft32(x1&k1, 1)
	x1 = x1 ^ (x2 | k2)

	return uint64(x1)<<32 | uint64(x2)
}

func flinv(y, k uint64) uint64 {
	y1 := uint32(y >> 32)
	y2 := uint32(y)
	k1 := uint32(k >> 32)
	k2 := uint32(k)

	y1 = y1 ^ (y2 | k2)
	y2 = y2 ^ bits.RotateLeft32(y1&k1, 1)

	return uint64(y1)<<32 | uint64(y2)
}

// rotl128 rotates a 128-bit value (h||l) left by n bits.
func rotl128(h, l uint64, n uint) (uint64, uint64) {
	if n >= 64 {
		h, l = l, h
		n -= 64
	}

	if n == 0 {
		return h, l
	}

	return (h << n) | (l >> (64 - n)), (l << n) | (h >> (64 - n))
}

func computeKA(klh, kll, krh, krl uint64) (uint64, uint64) {
	d1 := klh ^ krh
	d2 := kll ^ krl

	d2 = d2 ^ fFunc(d1, sigma1)
	d1 = d1 ^ fFunc(d2, sigma2)

	d1 = d1 ^ klh
	d2 = d2 ^ kll

	d2 = d2 ^ fFunc(d1, sigma3)
	d1 = d1 ^ fFunc(d2, sigma4)

	return d1, d2
}

func computeKB(kah, kal, krh, krl uint64) (uint64, uint64) {
	d1 := kah ^ krh
	d2 := kal ^ krl

	d2 = d2 ^ fFunc(d1, sigma5)
	d1 = d1 ^ fFunc(d2, sigma6)

	return d1, d2
}

func newCamellia128(key []byte) (*camelliaCipher, error) {
	c := &camelliaCipher{rounds: 18}

	klh := binary.BigEndian.Uint64(key[0:8])
	kll := binary.BigEndian.Uint64(key[8:16])

	kah, kal := computeKA(klh, kll, 0, 0)

	// 128-bit key schedule from RFC 3713.
	c.kw[0], c.kw[1] = klh, kll
	c.k[0], c.k[1] = kah, kal
	c.k[2], c.k[3] = rotl128(klh, kll, 15)
	c.k[4], c.k[5] = rotl128(kah, kal, 15)
	c.ke[0], c.ke[1] = rotl128(kah, kal, 30)
	c.k[6], c.k[7] = rotl128(klh, kll, 45)
	c.k[8], _ = rotl128(kah, kal, 45)
	_, c.k[9] = rotl128(klh, kll, 60)
	c.k[10], c.k[11] = rotl128(kah, kal, 60)
	c.ke[2], c.ke[3] = rotl128(klh, kll, 77)
	c.k[12], c.k[13] = rotl128(klh, kll, 94)
	c.k[14], c.k[15] = rotl128(kah, kal, 94)
	c.k[16], c.k[17] = rotl128(klh, kll, 111)
	c.kw[2], c.kw[3] = rotl128(kah, kal, 111)

	return c, nil
}

func newCamellia256(key []byte) (*camelliaCipher, error) {
	c := &camelliaCipher{rounds: 24}

	klh := binary.BigEndian.Uint64(key[0:8])
	kll := binary.BigEndian.Uint64(key[8:16])
	krh := binary.BigEndian.Uint64(key[16:24])
	krl := binary.BigEndian.Uint64(key[24:32])

	kah, kal := computeKA(klh, kll, krh, krl)
	kbh, kbl := computeKB(kah, kal, krh, krl)

	// 256-bit key schedule from RFC 3713.
	c.kw[0], c.kw[1] = klh, kll
	c.k[0], c.k[1] = kbh, kbl
	c.k[2], c.k[3] = rotl128(krh, krl, 15)
	c.k[4], c.k[5] = rotl128(kah, kal, 15)
	c.ke[0], c.ke[1] = rotl128(krh, krl, 30)
	c.k[6], c.k[7] = rotl128(kbh, kbl, 30)
	c.k[8], c.k[9] = rotl128(klh, kll, 45)
	c.k[10], c.k[11] = rotl128(kah, kal, 45)
	c.ke[2], c.ke[3] = rotl128(klh, kll, 60)
	c.k[12], c.k[13] = rotl128(krh, krl, 60)
	c.k[14], c.k[15] = rotl128(kbh, kbl, 60)
	c.k[16], c.k[17] = rotl128(klh, kll, 77)
	c.ke[4], c.ke[5] = rotl128(kah, kal, 77)
	c.k[18], c.k[19] = rotl128(krh, krl, 94)
	c.k[20], c.k[21] = rotl128(kah, kal, 94)
	c.k[22], c.k[23] = rotl128(klh, kll, 111)
	c.kw[2], c.kw[3] = rotl128(kbh, kbl, 111)

	return c, nil
}

func (c *camelliaCipher) BlockSize() int {
	return camelliaBlockSize
}

func (c *camelliaCipher) Encrypt(dst, src []byte) {
	if len(src) < camelliaBlockSize {
		panic("camellia: input not full block")
	}

	if len(dst) < camelliaBlockSize {
		panic("camellia: output not full block")
	}

	d1 := binary.BigEndian.Uint64(src[0:8])
	d2 := binary.BigEndian.Uint64(src[8:16])

	d1 ^= c.kw[0]
	d2 ^= c.kw[1]

	d2 ^= fFunc(d1, c.k[0])
	d1 ^= fFunc(d2, c.k[1])
	d2 ^= fFunc(d1, c.k[2])
	d1 ^= fFunc(d2, c.k[3])
	d2 ^= fFunc(d1, c.k[4])
	d1 ^= fFunc(d2, c.k[5])

	d1 = fl(d1, c.ke[0])
	d2 = flinv(d2, c.ke[1])

	d2 ^= fFunc(d1, c.k[6])
	d1 ^= fFunc(d2, c.k[7])
	d2 ^= fFunc(d1, c.k[8])
	d1 ^= fFunc(d2, c.k[9])
	d2 ^= fFunc(d1, c.k[10])
	d1 ^= fFunc(d2, c.k[11])

	d1 = fl(d1, c.ke[2])
	d2 = flinv(d2, c.ke[3])

	d2 ^= fFunc(d1, c.k[12])
	d1 ^= fFunc(d2, c.k[13])
	d2 ^= fFunc(d1, c.k[14])
	d1 ^= fFunc(d2, c.k[15])
	d2 ^= fFunc(d1, c.k[16])
	d1 ^= fFunc(d2, c.k[17])

	if c.rounds == 24 {
		d1 = fl(d1, c.ke[4])
		d2 = flinv(d2, c.ke[5])

		d2 ^= fFunc(d1, c.k[18])
		d1 ^= fFunc(d2, c.k[19])
		d2 ^= fFunc(d1, c.k[20])
		d1 ^= fFunc(d2, c.k[21])
		d2 ^= fFunc(d1, c.k[22])
		d1 ^= fFunc(d2, c.k[23])
	}

	d2 ^= c.kw[2]
	d1 ^= c.kw[3]

	// Output is D2 || D1 (swapped).
	binary.BigEndian.PutUint64(dst[0:8], d2)
	binary.BigEndian.PutUint64(dst[8:16], d1)
}

func (c *camelliaCipher) Decrypt(dst, src []byte) {
	if len(src) < camelliaBlockSize {
		panic("camellia: input not full block")
	}

	if len(dst) < camelliaBlockSize {
		panic("camellia: output not full block")
	}

	// Ciphertext was stored as D2||D1.
	d2 := binary.BigEndian.Uint64(src[0:8])
	d1 := binary.BigEndian.Uint64(src[8:16])

	d2 ^= c.kw[2]
	d1 ^= c.kw[3]

	if c.rounds == 24 {
		d1 ^= fFunc(d2, c.k[23])
		d2 ^= fFunc(d1, c.k[22])
		d1 ^= fFunc(d2, c.k[21])
		d2 ^= fFunc(d1, c.k[20])
		d1 ^= fFunc(d2, c.k[19])
		d2 ^= fFunc(d1, c.k[18])

		d2 = fl(d2, c.ke[5])
		d1 = flinv(d1, c.ke[4])
	}

	d1 ^= fFunc(d2, c.k[17])
	d2 ^= fFunc(d1, c.k[16])
	d1 ^= fFunc(d2, c.k[15])
	d2 ^= fFunc(d1, c.k[14])
	d1 ^= fFunc(d2, c.k[13])
	d2 ^= fFunc(d1, c.k[12])

	d2 = fl(d2, c.ke[3])
	d1 = flinv(d1, c.ke[2])

	d1 ^= fFunc(d2, c.k[11])
	d2 ^= fFunc(d1, c.k[10])
	d1 ^= fFunc(d2, c.k[9])
	d2 ^= fFunc(d1, c.k[8])
	d1 ^= fFunc(d2, c.k[7])
	d2 ^= fFunc(d1, c.k[6])

	d2 = fl(d2, c.ke[1])
	d1 = flinv(d1, c.ke[0])

	d1 ^= fFunc(d2, c.k[5])
	d2 ^= fFunc(d1, c.k[4])
	d1 ^= fFunc(d2, c.k[3])
	d2 ^= fFunc(d1, c.k[2])
	d1 ^= fFunc(d2, c.k[1])
	d2 ^= fFunc(d1, c.k[0])

	d1 ^= c.kw[0]
	d2 ^= c.kw[1]

	binary.BigEndian.PutUint64(dst[0:8], d1)
	binary.BigEndian.PutUint64(dst[8:16], d2)
}
