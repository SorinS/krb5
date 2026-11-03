package pac

import (
	"bytes"
	"fmt"

	"github.com/go-krb5/x/rpc/mstypes"
	"github.com/go-krb5/x/rpc/ndr"
)

// Claims reference: https://msdn.microsoft.com/en-us/library/hh553895.aspx

// DeviceClaimsInfo implements https://msdn.microsoft.com/en-us/library/hh554226.aspx
type DeviceClaimsInfo struct {
	ClaimsSetMetadata mstypes.ClaimsSetMetadata
	ClaimsSet         mstypes.ClaimsSet
}

// Unmarshal bytes into the DeviceClaimsInfo struct.
func (k *DeviceClaimsInfo) Unmarshal(b []byte) (err error) {
	dec := ndr.NewDecoder(bytes.NewReader(b))
	m := new(mstypes.ClaimsSetMetadata)

	err = dec.Decode(m)
	if err != nil {
		err = fmt.Errorf("error unmarshalling DeviceClaimsInfo ClaimsSetMetadata: %w", err)
		return
	}

	k.ClaimsSetMetadata = *m

	k.ClaimsSet, err = claimsSet(&k.ClaimsSetMetadata)
	if err != nil {
		err = fmt.Errorf("error unmarshalling DeviceClaimsInfo ClaimsSet: %w", err)
	}

	return
}
