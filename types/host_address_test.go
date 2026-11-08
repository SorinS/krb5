package types

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/SorinS/krb5/iana/addrtype"
)

func TestGetHostAddress(t *testing.T) {
	tests := []struct {
		str    string
		ipType int32
		hex    string
	}{
		{"192.168.1.100", addrtype.IPv4, "c0a80164"},
		{"127.0.0.1", addrtype.IPv4, "7f000001"},
		{"[fe80::1cf3:b43b:df29:d43e]", addrtype.IPv6, "fe800000000000001cf3b43bdf29d43e"},
	}
	for _, test := range tests {
		h, err := GetHostAddress(test.str + ":1234")
		assert.NoError(t, err)

		assert.Equal(t, test.ipType, h.AddrType)
		assert.Equal(t, test.hex, hex.EncodeToString(h.Address))
	}
}

// A NetBIOS name alone counts as no addresses (upstream PR 492); with
// another address, or two names, it does not.
func TestHostAddressesNetBIOSOnly(t *testing.T) {
	t.Parallel()

	nb := HostAddress{AddrType: addrtype.NetBios, Address: []byte("HOST            ")}
	ip := HostAddress{AddrType: addrtype.IPv4, Address: []byte{127, 0, 0, 1}}

	assert.True(t, HostAddressesNetBIOSOnly([]HostAddress{nb}))
	assert.False(t, HostAddressesNetBIOSOnly([]HostAddress{nb, ip}))
	assert.False(t, HostAddressesNetBIOSOnly([]HostAddress{ip}))
	assert.False(t, HostAddressesNetBIOSOnly(nil))
	assert.False(t, HostAddressesNetBIOSOnly([]HostAddress{nb, nb}))
}
