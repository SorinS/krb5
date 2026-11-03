package ldap

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Filters' BER (RFC 4511 4.5.1.7), checked by hand against the ASN.1.
func TestEncodeFilter(t *testing.T) {
	t.Parallel()

	for _, v := range []struct{ filter, der string }{
		// present [7] "objectClass"
		{"(objectClass=*)", "870b6f626a656374436c617373"},
		// equalityMatch [3] { "cn", "alice" }
		{"(cn=alice)", "a30b0402636e0405616c696365"},
		// and [0] { equality, not [2] { equality } }
		{"(&(cn=a)(!(sn=b)))", "a014" + "a3070402636e040161" + "a209" + "a3070402736e040162"},
		// or [1], >= [5], <= [6], approx [8]
		{"(|(a>=1)(b<=2)(c~=3))", "a118" + "a506040161040131" + "a606040162040132" + "a806040163040133"},
		// substrings [4] { "cn", { initial [0] "al", any [1] "i", final [2] "e" } }
		{"(cn=al*i*e)", "a410" + "0402636e" + "300a" + "8002616c" + "810169" + "820165"},
		// binary values escaped
		{`(objectSid=\01\05\00)`, "a3100409" + hex.EncodeToString([]byte("objectSid")) + "0403010500"},
	} {
		got, err := encodeFilter(v.filter)
		require.NoError(t, err, v.filter)

		assert.Equal(t, v.der, hex.EncodeToString(got), v.filter)
	}

	for _, bad := range []string{"cn=a", "(cn=a", "(&(cn=a)", "(cn)", `(cn=\0)`, `(cn=\zz)`, "(cn=a)x"} {
		_, err := encodeFilter(bad)
		assert.Error(t, err, bad)
	}
}

// BER as servers send it: long-form lengths (Active Directory's 4-byte
// ones) read; malformed lengths refused.
func TestReadTLV(t *testing.T) {
	t.Parallel()

	b, _ := hex.DecodeString("3084000000050201010400")
	m, rest, err := readTLV(b)
	require.NoError(t, err)
	assert.Empty(t, rest)
	assert.Equal(t, byte(0x30), m.tag)

	es, err := elements(m.body)
	require.NoError(t, err)
	require.Len(t, es, 2)

	v, err := decInt(es[0])
	require.NoError(t, err)
	assert.Equal(t, int64(1), v)

	for _, bad := range []string{"30", "3080", "3085000000000000", "3005020101", "1f0100"} {
		b, _ := hex.DecodeString(bad)
		_, _, err := readTLV(b)
		assert.Error(t, err, bad)
	}

	for _, n := range []int64{0, 1, 127, 128, 255, 256, -1, -128, -129, 1 << 40} {
		b := encInt(0x02, n)
		m, _, err := readTLV(b)
		require.NoError(t, err)

		got, err := decInt(m)
		require.NoError(t, err)
		assert.Equal(t, n, got)
	}

	long := make([]byte, 300)
	m, _, err = readTLV(encOctets(0x04, long))
	require.NoError(t, err)
	assert.Len(t, m.body, 300)
}

func TestSID(t *testing.T) {
	t.Parallel()

	for _, s := range []string{"S-1-5-21-3167651404-3865080224-2280184895-1105", "S-1-5-18", "S-1-1-0", "S-1-5-21-0-0-0-496"} {
		b, err := SIDBytes(s)
		require.NoError(t, err)

		back, err := SIDString(b)
		require.NoError(t, err)
		assert.Equal(t, s, back)
	}

	b, err := SIDBytes("S-1-5-32-544")
	require.NoError(t, err)
	assert.Equal(t, "01020000000000052000000020020000", hex.EncodeToString(b), "BUILTIN\\Administrators")

	for _, bad := range []string{"", "S-1", "X-1-5", "S-1-5-x", "S-300-5-1"} {
		_, err := SIDBytes(bad)
		assert.Error(t, err, bad)
	}

	_, err = SIDString([]byte{1, 2, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0})
	assert.Error(t, err, "a short SID")
}

// A search result entry: its DN and every value of each attribute.
func TestDecodeEntry(t *testing.T) {
	t.Parallel()

	attrs := enc(0x30,
		enc(0x30, encOctets(0x04, []byte("cn")), enc(0x31, encOctets(0x04, []byte("alice")))),
		enc(0x30, encOctets(0x04, []byte("member")), enc(0x31, encOctets(0x04, []byte("a")), encOctets(0x04, []byte("b")))))
	body := append(encOctets(0x04, []byte("CN=alice,DC=goose,DC=test")), attrs...)

	e, err := decodeEntry(body)
	require.NoError(t, err)
	assert.Equal(t, "CN=alice,DC=goose,DC=test", e.DN)
	assert.Equal(t, "alice", e.Get("cn"))
	assert.Len(t, e.Attributes["member"], 2)
	assert.Equal(t, "", e.Get("absent"))
}
