package xpress

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type vector struct {
	format, engine, size int
	sum                  string
	compressed           []byte
}

// testdata/windows.txt.gz: what Windows' RtlCompressBuffer made of inputs
// of many sizes and kinds (test/ad/xpress.ps1), both formats, both
// engines, the inputs' SHA-256 kept.
func windowsVectors(t *testing.T) []vector {
	t.Helper()

	f, err := os.Open("testdata/windows.txt.gz")
	require.NoError(t, err)

	defer f.Close()

	z, err := gzip.NewReader(f)
	require.NoError(t, err)

	var vs []vector

	sc := bufio.NewScanner(z)
	sc.Buffer(nil, 1<<20)

	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "#") {
			continue
		}

		w := strings.Fields(sc.Text())
		require.Len(t, w, 5)

		var v vector

		v.format, _ = strconv.Atoi(w[0])
		v.engine, _ = strconv.Atoi(w[1])
		v.size, _ = strconv.Atoi(w[2])
		v.sum = w[3]
		v.compressed, err = hex.DecodeString(w[4])
		require.NoError(t, err)

		vs = append(vs, v)
	}

	require.NoError(t, sc.Err())
	require.Len(t, vs, 412)

	return vs
}

func decompress(v vector, c []byte, size int) ([]byte, error) {
	if v.format == 3 {
		return Decompress(c, size)
	}

	return DecompressHuffman(c, size)
}

func TestWindowsVectors(t *testing.T) {
	t.Parallel()

	formats := map[int]int{}

	for _, v := range windowsVectors(t) {
		out, err := decompress(v, v.compressed, v.size)
		require.NoError(t, err, "format %d engine %d size %d", v.format, v.engine, v.size)

		sum := sha256.Sum256(out)
		assert.Equal(t, v.sum, hex.EncodeToString(sum[:]), "format %d engine %d size %d", v.format, v.engine, v.size)

		formats[v.format]++
	}

	assert.Equal(t, 176, formats[3])
	assert.Equal(t, 236, formats[4])
}

// Cut short, or asked for more than it holds, the data is refused.
func TestCorrupt(t *testing.T) {
	t.Parallel()

	for i, v := range windowsVectors(t) {
		if i%7 != 0 || v.size < 16 {
			continue
		}

		for _, cut := range []int{1, len(v.compressed) / 2, len(v.compressed) - 1} {
			if cut >= len(v.compressed) {
				continue
			}

			out, err := decompress(v, v.compressed[:cut], v.size)
			if err == nil {
				// The data may end in bits that make no output; the output is
				// then still the whole input.
				sum := sha256.Sum256(out)
				assert.Equal(t, v.sum, hex.EncodeToString(sum[:]), "format %d size %d cut %d", v.format, v.size, cut)
			}
		}

		_, err := decompress(v, v.compressed, v.size+4096)
		assert.ErrorIs(t, err, ErrCorrupt, "format %d size %d, more asked", v.format, v.size)
	}

	_, err := DecompressHuffman(nil, MaxSize+1)
	assert.Error(t, err)

	_, err = Decompress(nil, -1)
	assert.Error(t, err)

	// An incomplete Huffman code (one symbol of length 1) is refused.
	b := make([]byte, 256+8)
	b[0] = 1
	_, err = DecompressHuffman(b, 10)
	assert.ErrorIs(t, err, ErrCorrupt)

	// A match before the start of the output.
	_, err = Decompress([]byte{0, 0, 0, 0x80, 0x08, 0x00}, 4)
	assert.ErrorIs(t, err, ErrCorrupt)
}

// MS-XCA 3.1's examples of plain LZ77.
func TestSpecExamples(t *testing.T) {
	t.Parallel()

	abc := strings.Repeat("abc", 100)

	out, err := Decompress([]byte{0xff, 0xff, 0xff, 0x1f, 0x61, 0x62, 0x63, 0x17, 0x00, 0x0f, 0xff, 0x26, 0x01}, len(abc))
	require.NoError(t, err)
	assert.Equal(t, abc, string(out))

	alpha := "abcdefghijklmnopqrstuvwxyz"
	in := append([]byte{0x3f, 0x00, 0x00, 0x00}, alpha...)

	out, err = Decompress(in, len(alpha))
	require.NoError(t, err)
	assert.Equal(t, alpha, string(out))
}
