package rfc6803_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/crypto/common"
	"github.com/go-krb5/krb5/crypto/rfc6803"
)

// TestCamelliaCipher verifies the Camellia block cipher against RFC 3713 test vectors.
func TestCamelliaCipher(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name       string
		key        string
		plaintext  string
		ciphertext string
	}{
		{
			name:       "128-bit key",
			key:        "0123456789ABCDEFFEDCBA9876543210",
			plaintext:  "0123456789ABCDEFFEDCBA9876543210",
			ciphertext: "67673138549669730857065648EABE43",
		},
		{
			name:       "256-bit key",
			key:        "0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF",
			plaintext:  "0123456789ABCDEFFEDCBA9876543210",
			ciphertext: "9ACC237DFF16D76C20EF7C919E3A7509",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, _ := hex.DecodeString(test.key)
			plaintext, _ := hex.DecodeString(test.plaintext)
			expectedCT, _ := hex.DecodeString(test.ciphertext)

			block, err := rfc6803.NewCamelliaCipher(key)
			require.NoError(t, err)

			ct := make([]byte, 16)
			block.Encrypt(ct, plaintext)
			assert.Equal(t, strings.ToLower(test.ciphertext), hex.EncodeToString(ct), "encryption mismatch")

			pt := make([]byte, 16)
			block.Decrypt(pt, expectedCT)
			assert.Equal(t, strings.ToLower(test.plaintext), hex.EncodeToString(pt), "decryption mismatch")
		})
	}
}

// TestStringToKey verifies string-to-key derivation against RFC 6803 test vectors.
func TestStringToKey(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name       string
		iterations uint32
		passphrase string
		salt       string
		key128     string
		key256     string
	}{
		{
			name:       "iteration count 1",
			iterations: 1,
			passphrase: "password",
			salt:       "ATHENA.MIT.EDUraeburn",
			key128:     "57D0297298FFD9D35DE5A47FB4BDE24B",
			key256:     "B9D6828B2056B7BE656D88A123B1FAC68214AC2B727ECF5F69AFE0C4DF2A6D2C",
		},
		{
			name:       "iteration count 2",
			iterations: 2,
			passphrase: "password",
			salt:       "ATHENA.MIT.EDUraeburn",
			key128:     "73F1B53AA0F310F93B1DE8CCAA0CB152",
			key256:     "83FC5866E5F8F4C6F38663C65C87549F342BC47ED394DC9D3CD4D163ADE375E3",
		},
		{
			name:       "iteration count 1200",
			iterations: 1200,
			passphrase: "password",
			salt:       "ATHENA.MIT.EDUraeburn",
			key128:     "8E571145452855575FD916E7B04487AA",
			key256:     "77F421A6F25E138395E837E5D85D385B4C1BFD772E112CD9208CE72A530B15E6",
		},
		{
			name:       "iteration count 5 with binary salt",
			iterations: 5,
			passphrase: "password",
			salt:       "0x1234567878563412",
			key128:     "00498FD916BFC1C2B1031C170801B381",
			key256:     "11083A00BDFE6A41B2F19716D6202F0AFA94289AFE8B27A049BD28B1D76C389A",
		},
		{
			name:       "64 char passphrase",
			iterations: 1200,
			passphrase: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			salt:       "pass phrase equals block size",
			key128:     "8BF6C3EF709B981DBB585D086843BE05",
			key256:     "119FE2A1CB0B1BE010B9067A73DB63ED4665B4E53A98D17803 5DCFE843A6B9B0",
		},
		{
			name:       "65 char passphrase",
			iterations: 1200,
			passphrase: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			salt:       "pass phrase exceeds block size",
			key128:     "5752AC8D6AD1CCFE8430B312871C2F74",
			key256:     "614D5DFC0BA6D390B412B89AE4D5B088B612B316510994679DDB4383C7126DDF",
		},
		{
			name:       "UTF-8 passphrase (g-clef)",
			iterations: 50,
			passphrase: "\xF0\x9D\x84\x9E",
			salt:       "EXAMPLE.COMpianist",
			key128:     "CC75C7FD260F1C1658011FCC0D560616",
			key256:     "163B768C6DB148B4EEC7163DF5AED70E206B68CEC078BC069ED68A7ED36B1ECC",
		},
	}

	t.Run("Camellia128", func(t *testing.T) {
		var e crypto.Camellia128CtsCmac

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				salt := decodeHex(test.salt)

				k, err := e.StringToKey(test.passphrase, salt, common.IterationsToS2Kparams(test.iterations))
				require.NoError(t, err)

				assert.Equal(t, strings.ToLower(test.key128), hex.EncodeToString(k))
			})
		}
	})

	t.Run("Camellia256", func(t *testing.T) {
		var e crypto.Camellia256CtsCmac

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				salt := decodeHex(test.salt)

				k, err := e.StringToKey(test.passphrase, salt, common.IterationsToS2Kparams(test.iterations))
				require.NoError(t, err)

				assert.Equal(t, strings.ToLower(strings.ReplaceAll(test.key256, " ", "")), hex.EncodeToString(k))
			})
		}
	})
}

// TestKeyDerivation verifies key derivation against RFC 6803 test vectors.
func TestKeyDerivation(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name     string
		baseKey  string
		usage    []byte
		expected string
	}{
		{
			name:     "128-bit Kc usage 2",
			baseKey:  "57D0297298FFD9D35DE5A47FB4BDE24B",
			usage:    []byte{0x00, 0x00, 0x00, 0x02, 0x99},
			expected: "D155775A209D05F02B38D42A389E5A56",
		},
		{
			name:     "128-bit Ke usage 2",
			baseKey:  "57D0297298FFD9D35DE5A47FB4BDE24B",
			usage:    []byte{0x00, 0x00, 0x00, 0x02, 0xAA},
			expected: "64DF83F85A532F17577D8C37035796AB",
		},
		{
			name:     "128-bit Ki usage 2",
			baseKey:  "57D0297298FFD9D35DE5A47FB4BDE24B",
			usage:    []byte{0x00, 0x00, 0x00, 0x02, 0x55},
			expected: "3E4FBDF30FB8259C425CB6C96F1F4635",
		},
		{
			name:     "256-bit Kc usage 2",
			baseKey:  "B9D6828B2056B7BE656D88A123B1FAC68214AC2B727ECF5F69AFE0C4DF2A6D2C",
			usage:    []byte{0x00, 0x00, 0x00, 0x02, 0x99},
			expected: "E467F9A9552BC7D3155A6220AF9C19220EEED4FF78B0D1E6A1544991461A9E50",
		},
		{
			name:     "256-bit Ke usage 2",
			baseKey:  "B9D6828B2056B7BE656D88A123B1FAC68214AC2B727ECF5F69AFE0C4DF2A6D2C",
			usage:    []byte{0x00, 0x00, 0x00, 0x02, 0xAA},
			expected: "412AEFC362A7285FC3966C6A5181E7605AE675235B6D549FBFC9AB6630A4C604",
		},
		{
			name:     "256-bit Ki usage 2",
			baseKey:  "B9D6828B2056B7BE656D88A123B1FAC68214AC2B727ECF5F69AFE0C4DF2A6D2C",
			usage:    []byte{0x00, 0x00, 0x00, 0x02, 0x55},
			expected: "FA624FA0E523993FA388AEFDC67E67EBCD8C08E8A0246B1D73B0D1DD9FC582B0",
		},
	}

	t.Run("128-bit", func(t *testing.T) {
		var e crypto.Camellia128CtsCmac

		for _, test := range tests {
			if len(test.baseKey) > 32 {
				continue
			}

			t.Run(test.name, func(t *testing.T) {
				key, _ := hex.DecodeString(test.baseKey)

				dk, err := e.DeriveKey(key, test.usage)
				require.NoError(t, err)

				assert.Equal(t, strings.ToLower(test.expected), hex.EncodeToString(dk))
			})
		}
	})

	t.Run("256-bit", func(t *testing.T) {
		var e crypto.Camellia256CtsCmac

		for _, test := range tests {
			if len(test.baseKey) <= 32 {
				continue
			}

			t.Run(test.name, func(t *testing.T) {
				key, _ := hex.DecodeString(test.baseKey)

				dk, err := e.DeriveKey(key, test.usage)
				require.NoError(t, err)

				assert.Equal(t, strings.ToLower(test.expected), hex.EncodeToString(dk))
			})
		}
	})
}

// TestChecksumCamellia128 verifies CMAC checksum against RFC 6803 test vectors.
func TestChecksumCamellia128(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name     string
		key      string
		usage    uint32
		data     string
		checksum string
	}{
		{
			name:     "cmac-camellia128 test 1",
			key:      "1DC46A8D763F4F93742BCBA3387576C3",
			usage:    7,
			data:     "abcdefghijk",
			checksum: "1178E6C5C47A8C1AE0C4B9C7D4EB7B6B",
		},
		{
			name:     "cmac-camellia128 test 2",
			key:      "5027BC231D0F3A9D23333F1CA6FDBE7C",
			usage:    8,
			data:     "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			checksum: "D1B34F7004A731F23A0C00BF6C3F753A",
		},
	}

	var e crypto.Camellia128CtsCmac

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, _ := hex.DecodeString(test.key)

			hash, err := e.GetChecksumHash(key, []byte(test.data), test.usage)
			require.NoError(t, err)

			assert.Equal(t, strings.ToLower(test.checksum), hex.EncodeToString(hash))

			assert.True(t, e.VerifyChecksum(key, []byte(test.data), hash, test.usage))
		})
	}
}

// TestChecksumCamellia256 verifies CMAC checksum against RFC 6803 test vectors.
func TestChecksumCamellia256(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name     string
		key      string
		usage    uint32
		data     string
		checksum string
	}{
		{
			name:     "cmac-camellia256 test 1",
			key:      "B61C86CC4E5D2757545AD423399FB7031ECAB913CBB900BD7A3C6DD8BF92015B",
			usage:    9,
			data:     "123456789",
			checksum: "87A12CFD2B96214810F01C826E7744B1",
		},
		{
			name:     "cmac-camellia256 test 2",
			key:      "32164C5B434D1D1538E4CFD9BE8040FE8C4AC7ACC4B93D3314D2133668147A05",
			usage:    10,
			data:     "!@#$%^&*()!@#$%^&*()!@#$%^&*()",
			checksum: "3FA0B42355E52B189187294AA252AB64",
		},
	}

	var e crypto.Camellia256CtsCmac

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, _ := hex.DecodeString(test.key)

			hash, err := e.GetChecksumHash(key, []byte(test.data), test.usage)
			require.NoError(t, err)

			assert.Equal(t, strings.ToLower(test.checksum), hex.EncodeToString(hash))

			assert.True(t, e.VerifyChecksum(key, []byte(test.data), hash, test.usage))
		})
	}
}

// TestEncryptDecryptMessage verifies round-trip encryption/decryption.
func TestEncryptDecryptMessage(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name      string
		plaintext string
		usage     uint32
	}{
		{"empty", "", 2},
		{"short", "Hello", 2},
		{"block-sized", "0123456789abcdef", 2},
		{"multi-block", "The quick brown fox jumps over the lazy dog", 7},
	}

	t.Run("Camellia128", func(t *testing.T) {
		var e crypto.Camellia128CtsCmac
		key, _ := hex.DecodeString("0123456789ABCDEF0123456789ABCDEF")

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				plaintext := []byte(test.plaintext)

				_, ct, err := e.EncryptMessage(key, plaintext, test.usage)
				require.NoError(t, err)

				pt, err := e.DecryptMessage(key, ct, test.usage)
				require.NoError(t, err)

				assert.Equal(t, plaintext, pt)
			})
		}
	})

	t.Run("Camellia256", func(t *testing.T) {
		var e crypto.Camellia256CtsCmac
		key, _ := hex.DecodeString("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				plaintext := []byte(test.plaintext)

				_, ct, err := e.EncryptMessage(key, plaintext, test.usage)
				require.NoError(t, err)

				pt, err := e.DecryptMessage(key, ct, test.usage)
				require.NoError(t, err)

				assert.Equal(t, plaintext, pt)
			})
		}
	})
}

func decodeHex(s string) string {
	if strings.HasPrefix(s, "0x") {
		b, _ := hex.DecodeString(s[2:])
		return string(b)
	}

	return s
}
