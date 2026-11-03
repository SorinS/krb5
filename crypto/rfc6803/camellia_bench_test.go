package rfc6803

import "testing"

func BenchmarkCamellia256Encrypt(b *testing.B) {
	c, _ := NewCamelliaCipher(make([]byte, 32))
	buf := make([]byte, 16)

	b.SetBytes(16)

	for i := 0; i < b.N; i++ {
		c.Encrypt(buf, buf)
	}
}

func BenchmarkCamelliaF(b *testing.B) {
	x := uint64(1)
	for i := 0; i < b.N; i++ {
		x = fFunc(x, 0x0123456789abcdef)
	}

	sink = x
}

func BenchmarkCamelliaFTable(b *testing.B) {
	x := uint64(1)
	for i := 0; i < b.N; i++ {
		x = fFuncTable(x, 0x0123456789abcdef)
	}

	sink = x
}
