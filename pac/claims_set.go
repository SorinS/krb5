package pac

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/go-krb5/x/rpc/mstypes"
	"github.com/go-krb5/x/rpc/ndr"

	"github.com/SorinS/krb5/pac/xpress"
)

// claimsSet decodes the ClaimsSet in a CLAIMS_SET_METADATA (MS-ADTS
// 2.2.18.5), decompressing it first when it is compressed: Active
// Directory compresses large claims sets with LZ77+Huffman
// (COMPRESSION_FORMAT_XPRESS_HUFF, MS-XCA 2.2), to the
// UncompressedClaimsSetSize the metadata gives. Plain LZ77 is read too;
// LZNT1, which AD does not use, is refused.
func claimsSet(m *mstypes.ClaimsSetMetadata) (mstypes.ClaimsSet, error) {
	var c mstypes.ClaimsSet

	// No claims set (a device without claims, in a compound identity's
	// PAC): AD sends the metadata with a null claims set.
	if len(m.ClaimsSetBytes) == 0 {
		if m.ClaimsSetSize != 0 {
			return c, errors.New("no bytes available for ClaimsSet")
		}

		return c, nil
	}

	b := m.ClaimsSetBytes

	var err error

	switch m.CompressionFormat {
	case mstypes.CompressionFormatNone:
	case mstypes.CompressionFormatXPressHuff:
		b, err = xpress.DecompressHuffman(b, int(m.UncompressedClaimsSetSize))
	case mstypes.CompressionFormatXPress:
		b, err = xpress.Decompress(b, int(m.UncompressedClaimsSetSize))
	default:
		return c, fmt.Errorf("ClaimsSet compression format %d is not supported", m.CompressionFormat)
	}

	if err != nil {
		return c, fmt.Errorf("decompressing ClaimsSet: %w", err)
	}

	err = ndr.NewDecoder(bytes.NewReader(b)).Decode(&c)

	return c, err
}
