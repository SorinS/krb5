package crypto

import (
	"bufio"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/go-krb5/krb5/types"
)

// testdata/mit_crypto.txt is MIT's libk5crypto's output (krb5_c_prf,
// krb5_c_fx_cf2_simple, ...) on random keys and inputs, for every
// encryption type.
func TestMITCrypto(t *testing.T) {
	t.Parallel()

	f, err := os.Open("testdata/mit_crypto.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	h := func(s string) []byte {
		if s == "-" {
			return nil
		}

		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}

		return b
	}
	num := func(s string) int32 {
		n, err := strconv.Atoi(s)
		if err != nil {
			t.Fatal(err)
		}

		return int32(n)
	}

	var prfs, cf2s, others int

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		w := strings.Fields(sc.Text())
		if len(w) == 0 {
			continue
		}

		switch w[0] {
		case "prf":
			got, err := PRF(types.EncryptionKey{KeyType: num(w[1]), KeyValue: h(w[2])}, h(w[3]))
			if err != nil || hex.EncodeToString(got) != w[4] {
				t.Errorf("%s: got %x, %v", sc.Text(), got, err)
			}

			prfs++
		case "cf2":
			k1 := types.EncryptionKey{KeyType: num(w[1]), KeyValue: h(w[2])}
			k2 := types.EncryptionKey{KeyType: num(w[4]), KeyValue: h(w[5])}

			got, err := CF2(k1, w[3], k2, w[6])
			if err != nil || got.KeyType != k1.KeyType || hex.EncodeToString(got.KeyValue) != w[7] {
				t.Errorf("%s: got %x, %v", sc.Text(), got.KeyValue, err)
			}

			cf2s++
		case "s2k":
			// etype password salt params key
			e, err := GetEtype(num(w[1]))
			if err != nil {
				t.Fatal(err)
			}

			params := w[4]
			if params == "-" {
				params = e.GetDefaultStringToKeyParams()
			}

			got, err := e.StringToKey(string(h(w[2])), string(h(w[3])), params)

			if err != nil || hex.EncodeToString(got) != w[5] {
				t.Errorf("%s: got %x, %v", sc.Text(), got, err)
			}

			others++
		case "cksum":
			// etype ctype key usage data checksum
			e, err := GetChksumEtype(num(w[2]))
			if err != nil {
				t.Fatal(err)
			}

			got, err := e.GetChecksumHash(h(w[3]), h(w[5]), uint32(num(w[4])))
			if err != nil || hex.EncodeToString(got) != w[6] {
				t.Errorf("%s: got %x, %v", sc.Text(), got, err)
			}

			others++
		case "enc":
			// etype key usage plain ciphertext
			k := types.EncryptionKey{KeyType: num(w[1]), KeyValue: h(w[2])}
			plain := h(w[4])

			got, err := DecryptMessage(h(w[5]), k, uint32(num(w[3])))
			// DES3 keeps the zeros that pad to its block.
			if err != nil || len(got) < len(plain) || hex.EncodeToString(got[:len(plain)]) != hex.EncodeToString(plain) ||
				(k.KeyType != 16 && len(got) != len(plain)) {
				t.Errorf("%s: got %x, %v", sc.Text(), got, err)
			}

			if _, err := DecryptMessage(h(w[5]), k, uint32(num(w[3]))+1); err == nil {
				t.Errorf("%s: decrypts under the next usage", sc.Text())
			}

			others++
		}
	}

	if prfs != 48 || cf2s != 64 || others < 200 {
		t.Errorf("%d PRF, %d CF2 and %d other vectors", prfs, cf2s, others)
	}
}

func TestRFC8009PRF(t *testing.T) {
	t.Parallel()

	// RFC 8009 appendix A.
	k := types.EncryptionKey{KeyType: 19, KeyValue: h2b(t, "3705D96080C17728A0E800EAB6E0D23C")}

	got, err := PRF(k, []byte("test"))
	if err != nil || hex.EncodeToString(got) != strings.ToLower("9D188616F63852FE86915BB840B4A886FF3E6BB0F819B49B893393D393854295") {
		t.Errorf("got %x, %v", got, err)
	}
}

func h2b(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}

	return b
}
