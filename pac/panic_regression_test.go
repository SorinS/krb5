package pac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A PAC header claiming an enormous buffer count must be rejected before the
// slice is allocated, rather than attempting a multi-gigabyte make and
// crashing with OOM. The buffer count is attacker-controlled.
func TestPACType_Unmarshal_HugeCBuffers(t *testing.T) {
	// CBuffers = 0xFFFFFFFF (LE), Version = 0; only the 8-byte header follows.
	b := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00}

	var p PACType

	assert.NotPanics(t, func() {
		err := p.Unmarshal(b)
		assert.Error(t, err)
	})
}

// A UPN_DNS_INFO field whose offset/length point past the buffer (or wrap)
// must error, not panic on the slice.
func TestUPNDNSInfo_Unmarshal_OutOfBounds(t *testing.T) {
	// UPNLength=10, UPNOffset=100 (LE), rest zero; buffer is only 12 bytes.
	b := []byte{
		0x0A, 0x00, // UPNLength = 10
		0x64, 0x00, // UPNOffset = 100 (past the 12-byte buffer)
		0x00, 0x00, // DNSDomainNameLength
		0x00, 0x00, // DNSDomainNameOffset
		0x00, 0x00, 0x00, 0x00, // Flags
	}

	var u UPNDNSInfo

	assert.NotPanics(t, func() {
		err := u.Unmarshal(b)
		assert.Error(t, err)
	})
}
