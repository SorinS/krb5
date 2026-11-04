package pac

import (
	"testing"

	"github.com/go-krb5/x/rpc/mstypes"
)

// A device without claims: AD's compound identity PAC has a device claims
// buffer whose claims set is null.
func TestClaimsSetEmpty(t *testing.T) {
	t.Parallel()

	c, err := claimsSet(&mstypes.ClaimsSetMetadata{})
	if err != nil || len(c.ClaimsArrays) != 0 {
		t.Errorf("%+v, %v", c, err)
	}

	if _, err := claimsSet(&mstypes.ClaimsSetMetadata{ClaimsSetSize: 8}); err == nil {
		t.Error("a claims set announced and missing")
	}
}
