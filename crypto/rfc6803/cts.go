package rfc6803

import (
	"crypto/cipher"
	"errors"
	"fmt"
)

// CTS provides CBC ciphertext stealing encryption and decryption for any block cipher.

// CTSEncrypt encrypts plaintext using CBC with ciphertext stealing.
// Returns: next IV, ciphertext bytes, error.
func CTSEncrypt(block cipher.Block, iv, plaintext []byte) ([]byte, []byte, error) {
	bs := block.BlockSize()
	l := len(plaintext)

	mode := cipher.NewCBCEncrypter(block, iv)
	m := make([]byte, len(plaintext))
	copy(m, plaintext)

	if l <= bs {
		m = zeroPad(m, bs)
		mode.CryptBlocks(m, m)
		return m, m, nil
	}

	if l%bs == 0 {
		mode.CryptBlocks(m, m)
		nextIV := m[len(m)-bs:]
		rb := swapLastTwoBlocks(m, bs)
		return nextIV, rb, nil
	}

	m = zeroPad(m, bs)
	rb, pb, lb := tailBlocks(m, bs)

	var ct []byte

	if rb != nil {
		mode.CryptBlocks(rb, rb)
		iv = rb[len(rb)-bs:]
		mode = cipher.NewCBCEncrypter(block, iv)
		ct = append(ct, rb...)
	}

	mode.CryptBlocks(pb, pb)
	mode = cipher.NewCBCEncrypter(block, pb)
	mode.CryptBlocks(lb, lb)

	ct = append(ct, lb...)
	ct = append(ct, pb...)

	return lb, ct[:l], nil
}

// CTSDecrypt decrypts ciphertext using CBC with ciphertext stealing.
func CTSDecrypt(block cipher.Block, iv, ciphertext []byte) ([]byte, error) {
	bs := block.BlockSize()
	ct := make([]byte, len(ciphertext))
	copy(ct, ciphertext)

	if len(ct) < bs {
		return nil, fmt.Errorf("ciphertext too short: %d bytes, need at least %d", len(ct), bs)
	}

	if len(ct)%bs == 0 {
		if len(ct) > bs {
			ct = swapLastTwoBlocks(ct, bs)
		}

		mode := cipher.NewCBCDecrypter(block, iv)
		message := make([]byte, len(ct))
		mode.CryptBlocks(message, ct)

		return message[:len(ct)], nil
	}

	crb, cpb, clb := tailBlocks(ct, bs)
	v := make([]byte, len(iv))
	copy(v, iv)

	var message []byte

	if crb != nil {
		rb := make([]byte, len(crb))
		mode := cipher.NewCBCDecrypter(block, v)
		v = crb[len(crb)-bs:]
		mode.CryptBlocks(rb, crb)
		message = append(message, rb...)
	}

	pb := make([]byte, bs)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(pb, cpb)

	npb := bs - len(ct)%bs
	clb = append(clb, pb[len(pb)-npb:]...)

	lb := make([]byte, bs)
	mode = cipher.NewCBCDecrypter(block, v)
	mode.CryptBlocks(lb, clb)
	message = append(message, lb...)

	mode = cipher.NewCBCDecrypter(block, clb)
	mode.CryptBlocks(cpb, cpb)
	message = append(message, cpb...)

	return message[:len(ct)], nil
}

func tailBlocks(b []byte, bs int) ([]byte, []byte, []byte) {
	var lbs int
	if l := len(b) % bs; l == 0 {
		lbs = bs
	} else {
		lbs = l
	}

	lb := b[len(b)-lbs:]
	pb := b[len(b)-lbs-bs : len(b)-lbs]

	if len(b) > 2*bs {
		rb := b[:len(b)-lbs-bs]
		return rb, pb, lb
	}

	return nil, pb, lb
}

func swapLastTwoBlocks(b []byte, bs int) []byte {
	if len(b) <= bs {
		return b
	}

	rb, pb, lb := tailBlocks(b, bs)

	var out []byte
	if rb != nil {
		out = append(out, rb...)
	}

	out = append(out, lb...)
	out = append(out, pb...)

	return out
}

func zeroPad(b []byte, m int) []byte {
	if m <= 0 || len(b) == 0 {
		return b
	}

	if l := len(b) % m; l != 0 {
		n := m - l
		z := make([]byte, n)
		b = append(b, z...)
	}

	return b
}

// EncryptCTS encrypts plaintext using Camellia-CBC-CTS with an all-zero IV.
func EncryptCTS(key, plaintext []byte) ([]byte, []byte, error) {
	block, err := NewCamelliaCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating cipher: %w", err)
	}

	iv := make([]byte, block.BlockSize())

	return CTSEncrypt(block, iv, plaintext)
}

// DecryptCTS decrypts ciphertext using Camellia-CBC-CTS with an all-zero IV.
func DecryptCTS(key, ciphertext []byte) ([]byte, error) {
	block, err := NewCamelliaCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher: %w", err)
	}

	if len(ciphertext) < block.BlockSize() {
		return nil, errors.New("ciphertext is shorter than one block")
	}

	iv := make([]byte, block.BlockSize())

	return CTSDecrypt(block, iv, ciphertext)
}
