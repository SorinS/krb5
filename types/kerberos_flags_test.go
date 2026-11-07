package types

import (
	"testing"

	"github.com/go-krb5/x/encoding/asn1"
	"github.com/stretchr/testify/assert"

	"github.com/go-krb5/krb5/iana/flags"
)

func TestKerberosFlags_SetFlag(t *testing.T) {
	t.Parallel()

	b := []byte{byte(64), byte(0), byte(0), byte(16)}

	var f asn1.BitString
	SetFlag(&f, flags.Forwardable)
	SetFlag(&f, flags.RenewableOK)
	assert.Equal(t, b, f.Bytes)
}

func TestKerberosFlags_UnsetFlag(t *testing.T) {
	t.Parallel()

	b := []byte{byte(64), byte(0), byte(0), byte(0)}

	var f asn1.BitString
	SetFlag(&f, flags.Forwardable)
	SetFlag(&f, flags.RenewableOK)
	UnsetFlag(&f, flags.RenewableOK)
	assert.Equal(t, b, f.Bytes)
}

func TestKerberosFlags_IsFlagSet(t *testing.T) {
	t.Parallel()

	var f asn1.BitString
	SetFlag(&f, flags.Forwardable)
	SetFlag(&f, flags.RenewableOK)
	UnsetFlag(&f, flags.Proxiable)
	assert.True(t, IsFlagSet(&f, flags.Forwardable))
	assert.True(t, IsFlagSet(&f, flags.RenewableOK))
	assert.False(t, IsFlagSet(&f, flags.Proxiable))
}

// A flag bit beyond a short or empty BitString (as a malformed message may
// carry) must report "not set", never panic with an out-of-range index.
func TestKerberosFlags_IsFlagSet_OutOfRange(t *testing.T) {
	t.Parallel()

	assert.NotPanics(t, func() {
		assert.False(t, IsFlagSet(nil, flags.Forwardable))

		empty := asn1.BitString{}
		assert.False(t, IsFlagSet(&empty, flags.Forwardable)) // byte 0 of 0 bytes
		assert.False(t, IsFlagSet(&empty, flags.EncPARep))    // bit 15 -> byte 1

		oneByte := asn1.BitString{Bytes: []byte{0x80}, BitLength: 8}
		assert.True(t, IsFlagSet(&oneByte, 0))   // within range
		assert.False(t, IsFlagSet(&oneByte, 8))  // byte 1 of 1 byte
		assert.False(t, IsFlagSet(&oneByte, -1)) // negative bit
		assert.False(t, IsFlagSet(&oneByte, flags.EncPARep))
	})
}
