package pac

import (
	"encoding/hex"
	"testing"

	"github.com/go-krb5/x/rpc/mstypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/test/testdata"
)

const (
	ClaimsEntryIDStr            = "ad://ext/sAMAccountName:88d5d9085ea5c0c0"
	ClaimsEntryValueStr         = "testuser1"
	ClaimsEntryIDInt64          = "ad://ext/msDS-SupportedE:88d5dea8f1af5f19"
	ClaimsEntryValueInt64 int64 = 28
	ClaimsEntryIDUInt64         = "ad://ext/objectClass:88d5de791e7b27e6"
)

func TestPAC_ClientClaimsInfoStr_Unmarshal(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_ClientClaimsInfoStr)
	require.NoError(t, err)

	var k ClientClaimsInfo

	require.NoError(t, k.Unmarshal(b))

	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrayCount)
	assert.Equal(t, mstypes.ClaimsSourceTypeAD, k.ClaimsSet.ClaimsArrays[0].ClaimsSourceType)
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrays[0].ClaimsCount)
	assert.Equal(t, uint16(3), k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].Type)
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeString.ValueCount)
	assert.Equal(t, ClaimsEntryIDStr, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].ID)
	assert.Equal(t, []mstypes.LPWSTR{{Value: ClaimsEntryValueStr}}, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeString.Value)
	assert.Equal(t, mstypes.CompressionFormatNone, k.ClaimsSetMetadata.CompressionFormat)
}

func TestPAC_ClientClaimsMultiValueUint_Unmarshal(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_ClientClaimsInfoMultiUint)
	require.NoError(t, err)

	var k ClientClaimsInfo

	require.NoError(t, k.Unmarshal(b))

	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrayCount)
	assert.Equal(t, mstypes.ClaimsSourceTypeAD, k.ClaimsSet.ClaimsArrays[0].ClaimsSourceType)
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrays[0].ClaimsCount)
	assert.Equal(t, mstypes.ClaimTypeIDUInt64, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].Type)
	assert.Equal(t, uint32(4), k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeUInt64.ValueCount)
	assert.Equal(t, ClaimsEntryIDUInt64, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].ID)
	assert.Equal(t, []uint64{655369, 65543, 65542, 65536}, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeUInt64.Value)
	assert.Equal(t, mstypes.CompressionFormatNone, k.ClaimsSetMetadata.CompressionFormat)
}

func TestPAC_ClientClaimsInt_Unmarshal(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_ClientClaimsInfoInt)
	require.NoError(t, err)

	var k ClientClaimsInfo

	require.NoError(t, k.Unmarshal(b))

	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrayCount)
	assert.Equal(t, mstypes.ClaimsSourceTypeAD, k.ClaimsSet.ClaimsArrays[0].ClaimsSourceType)
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrays[0].ClaimsCount)
	assert.Equal(t, mstypes.ClaimTypeIDInt64, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].Type)
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeInt64.ValueCount)
	assert.Equal(t, ClaimsEntryIDInt64, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].ID)
	assert.Equal(t, []int64{ClaimsEntryValueInt64}, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeInt64.Value)
	assert.Equal(t, mstypes.CompressionFormatNone, k.ClaimsSetMetadata.CompressionFormat)
}

func TestPAC_ClientClaimsMultiValueStr_Unmarshal(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_ClientClaimsInfoMultiStr)
	require.NoError(t, err)

	var k ClientClaimsInfo

	require.NoError(t, k.Unmarshal(b))

	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrayCount)
	assert.Equal(t, mstypes.ClaimsSourceTypeAD, k.ClaimsSet.ClaimsArrays[0].ClaimsSourceType)
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrays[0].ClaimsCount)
	assert.Equal(t, mstypes.ClaimTypeIDString, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].Type)
	assert.Equal(t, uint32(4), k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeString.ValueCount)
	assert.Equal(t, "ad://ext/otherIpPhone:88d5de9f6b4af985", k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].ID)
	assert.Equal(t, []mstypes.LPWSTR{{Value: "str1"}, {Value: "str2"}, {Value: "str3"}, {Value: "str4"}}, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeString.Value)
	assert.Equal(t, mstypes.CompressionFormatNone, k.ClaimsSetMetadata.CompressionFormat)
}

func TestPAC_ClientClaimsInfoMultiEntry_Unmarshal(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_ClientClaimsInfoMulti)
	require.NoError(t, err)

	var k ClientClaimsInfo

	require.NoError(t, k.Unmarshal(b))

	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrayCount)
	assert.Equal(t, mstypes.ClaimsSourceTypeAD, k.ClaimsSet.ClaimsArrays[0].ClaimsSourceType)
	assert.Equal(t, uint32(2), k.ClaimsSet.ClaimsArrays[0].ClaimsCount)
	assert.Equal(t, uint16(1), k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].Type)
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeInt64.ValueCount)
	assert.Equal(t, ClaimsEntryIDInt64, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].ID)
	assert.Equal(t, []int64{int64(28)}, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeInt64.Value)
	assert.Equal(t, uint16(3), k.ClaimsSet.ClaimsArrays[0].ClaimEntries[1].Type)
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrays[0].ClaimEntries[1].TypeString.ValueCount)
	assert.Equal(t, ClaimsEntryIDStr, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[1].ID)
	assert.Equal(t, []mstypes.LPWSTR{{Value: ClaimsEntryValueStr}}, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[1].TypeString.Value)
	assert.Equal(t, mstypes.CompressionFormatNone, k.ClaimsSetMetadata.CompressionFormat)
}

// go-krb5's one compressed claims vector (LZ77+Huffman), which it decoded
// as HPACK's Huffman code and so could not read: the user's objectClass,
// sAMAccountName and sAMAccountType, as the uncompressed vectors have them.
func TestPAC_ClientClaimsInfoXPressHuff_Unmarshal(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_ClientClaimsInfo_XPRESS_HUFF)
	require.NoError(t, err)

	var k ClientClaimsInfo

	require.NoError(t, k.Unmarshal(b))
	assert.Equal(t, mstypes.CompressionFormatXPressHuff, k.ClaimsSetMetadata.CompressionFormat)
	require.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrayCount)

	a := k.ClaimsSet.ClaimsArrays[0]
	assert.Equal(t, mstypes.ClaimsSourceTypeAD, a.ClaimsSourceType)
	require.Len(t, a.ClaimEntries, 3)

	assert.Equal(t, "ad://ext/objectClass:88d5de791e7b27e6", a.ClaimEntries[0].ID)
	assert.Equal(t, mstypes.ClaimTypeIDUInt64, a.ClaimEntries[0].Type)
	assert.Equal(t, []uint64{655369, 65543, 65542, 65536}, a.ClaimEntries[0].TypeUInt64.Value)

	assert.Equal(t, "ad://ext/sAMAccountName:88d5d9085ea5c0c0", a.ClaimEntries[1].ID)
	assert.Equal(t, mstypes.ClaimTypeIDString, a.ClaimEntries[1].Type)
	assert.Equal(t, []mstypes.LPWSTR{{Value: "testuser1"}}, a.ClaimEntries[1].TypeString.Value)

	assert.Equal(t, "ad://ext/sAMAccountType:88d5de79a7ecf8c7", a.ClaimEntries[2].ID)
	assert.Equal(t, mstypes.ClaimTypeIDInt64, a.ClaimEntries[2].Type)
	assert.Equal(t, []int64{0x30000000}, a.ClaimEntries[2].TypeInt64.Value)

	// Cut short, the compressed set does not come to its size.
	assert.Error(t, k.Unmarshal(b[:len(b)-40]))
}
