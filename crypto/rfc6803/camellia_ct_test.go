package rfc6803

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The planes S-boxes are RFC 3713's, at every byte position and for every
// byte: s1 at the first and last, s2 = s1 <<< 1, s3 = s1 <<< 7 and
// s4(x) = s1(x <<< 1) at theirs; the other positions held at a value that
// is not changed by what is tried.
func TestCamelliaSboxes(t *testing.T) {
	t.Parallel()

	s := []func(byte) byte{
		func(x byte) byte { return sbox1[x] },
		func(x byte) byte { return rotl8(sbox1[x], 1) },
		func(x byte) byte { return rotl8(sbox1[x], 7) },
		func(x byte) byte { return sbox1[rotl8(x, 1)] },
	}
	which := []int{0, 1, 2, 3, 1, 2, 3, 0}

	for pos := 0; pos < 8; pos++ {
		for b := 0; b < 256; b++ {
			for _, rest := range []byte{0, 0x5a, 0xff} {
				var in [8]byte
				for i := range in {
					in[i] = rest
				}

				in[pos] = byte(b)

				out := sboxes(binary.BigEndian.Uint64(in[:]))

				var got [8]byte
				binary.BigEndian.PutUint64(got[:], out)

				for i := range in {
					require.Equal(t, s[which[i]](in[i]), got[i], "position %d byte %#x (others %#x)", i, in[i], rest)
				}
			}
		}
	}
}

// F, constant time, against the table F this package had: a million
// random inputs and keys.
func TestCamelliaFAgainstTable(t *testing.T) {
	t.Parallel()

	b := make([]byte, 16*1000000)
	_, err := rand.Read(b)
	require.NoError(t, err)

	for i := 0; i < len(b); i += 16 {
		x, k := binary.BigEndian.Uint64(b[i:]), binary.BigEndian.Uint64(b[i+8:])
		if fFunc(x, k) != fFuncTable(x, k) {
			t.Fatalf("F(%016x, %016x) = %016x, the table's %016x", x, k, fFunc(x, k), fFuncTable(x, k))
		}
	}
}

// RFC 3713 Appendix A, and the blocks, F values and CMAC tags of testdata/camellia.txt
// (every block checked against openssl enc -camellia-N-ecb when it was
// made): encryption, and decryption back.
func TestCamelliaVectors(t *testing.T) {
	t.Parallel()

	for _, v := range []struct{ key, pt, ct string }{
		{"0123456789abcdeffedcba9876543210", "0123456789abcdeffedcba9876543210", "67673138549669730857065648eabe43"},
		{"0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff", "0123456789abcdeffedcba9876543210", "9acc237dff16d76c20ef7c919e3a7509"},
	} {
		checkBlock(t, v.key, v.pt, v.ct)
	}

	f, err := os.Open("testdata/camellia.txt")
	require.NoError(t, err)

	defer f.Close()

	blocks, fs, cmacs := 0, 0, 0
	sc := bufio.NewScanner(f)

	for sc.Scan() {
		w := strings.Fields(sc.Text())
		if len(w) == 0 || strings.HasPrefix(w[0], "#") {
			continue
		}

		switch w[0] {
		case "block":
			checkBlock(t, w[1], w[2], w[3])
			blocks++
		case "cmac":
			k, _ := hex.DecodeString(w[2])
			var m []byte
			if w[3] != "-" {
				m, _ = hex.DecodeString(w[3])
			}
			want, _ := hex.DecodeString(w[4])
			b, err := NewCamelliaCipher(k)
			require.NoError(t, err)
			assert.Equal(t, want, CMAC(b, m), "CMAC with %s over %d bytes", w[2], len(m))
			cmacs++
		case "f":
			x, k, want := unhex64(t, w[1]), unhex64(t, w[2]), unhex64(t, w[3])
			assert.Equal(t, want, fFunc(x, k), "F(%s, %s)", w[1], w[2])
			fs++
		}
	}

	require.NoError(t, sc.Err())
	assert.Equal(t, 898, blocks)
	assert.Equal(t, 200, fs)
	assert.Positive(t, cmacs)
	t.Logf("%d blocks, %d F values, %d CMAC tags", blocks, fs, cmacs)
}

func unhex64(t *testing.T, s string) uint64 {
	b, err := hex.DecodeString(s)
	require.NoError(t, err)

	return binary.BigEndian.Uint64(b)
}

func checkBlock(t *testing.T, key, pt, ct string) {
	t.Helper()

	k, _ := hex.DecodeString(key)
	p, _ := hex.DecodeString(pt)
	c, _ := hex.DecodeString(ct)

	b, err := NewCamelliaCipher(k)
	require.NoError(t, err)

	out := make([]byte, 16)
	b.Encrypt(out, p)
	assert.Equal(t, c, out, "encrypt with %s", key)

	b.Decrypt(out, c)
	assert.Equal(t, p, out, "decrypt with %s", key)
}
