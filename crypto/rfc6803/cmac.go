package rfc6803

import (
	"crypto/cipher"
)

// CMAC computes a CMAC tag (SP 800-38B) using the provided block cipher.
func CMAC(block cipher.Block, data []byte) []byte {
	bs := block.BlockSize()
	k1, k2 := cmacSubkeys(block)

	n := (len(data) + bs - 1) / bs
	if n == 0 {
		n = 1
	}

	lastComplete := len(data) > 0 && len(data)%bs == 0
	lastBlock := make([]byte, bs)

	if lastComplete {
		copy(lastBlock, data[(n-1)*bs:])
		xorBytes(lastBlock, lastBlock, k1)
	} else {
		// Copy whatever remains and pad with 10...0.
		rem := len(data) - (n-1)*bs
		copy(lastBlock, data[(n-1)*bs:])
		lastBlock[rem] = 0x80
		xorBytes(lastBlock, lastBlock, k2)
	}

	x := make([]byte, bs)

	for i := 0; i < n-1; i++ {
		xorBytes(x, x, data[i*bs:(i+1)*bs])
		block.Encrypt(x, x)
	}

	xorBytes(x, x, lastBlock)
	block.Encrypt(x, x)

	return x
}

// cmacSubkeys generates CMAC subkeys K1 and K2 from the cipher key.
func cmacSubkeys(block cipher.Block) ([]byte, []byte) {
	bs := block.BlockSize()

	// L = CIPH_K(0^n)
	zeros := make([]byte, bs)
	l := make([]byte, bs)
	block.Encrypt(l, zeros)

	k1 := make([]byte, bs)
	shiftLeft(k1, l)

	if l[0]&0x80 != 0 {
		// R_b for 128-bit block cipher = 0x87
		k1[bs-1] ^= 0x87
	}

	k2 := make([]byte, bs)
	shiftLeft(k2, k1)

	if k1[0]&0x80 != 0 {
		k2[bs-1] ^= 0x87
	}

	return k1, k2
}

// shiftLeft shifts a byte slice left by one bit.
func shiftLeft(dst, src []byte) {
	for i := 0; i < len(src)-1; i++ {
		dst[i] = (src[i] << 1) | (src[i+1] >> 7)
	}

	dst[len(src)-1] = src[len(src)-1] << 1
}

// xorBytes XORs src1 and src2 into dst. All slices must be the same length.
func xorBytes(dst, src1, src2 []byte) {
	for i := range dst {
		dst[i] = src1[i] ^ src2[i]
	}
}
