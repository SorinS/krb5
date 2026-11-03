// Package xpress decompresses MS-XCA's formats (the Xpress Compression
// Algorithm): plain LZ77 (COMPRESSION_FORMAT_XPRESS, MS-XCA 2.4) and
// LZ77+Huffman (COMPRESSION_FORMAT_XPRESS_HUFF, MS-XCA 2.2), which Active
// Directory uses for large claims sets in a PAC (MS-ADTS 2.2.18.5).
package xpress

import (
	"encoding/binary"
	"errors"
)

// MaxSize bounds the decompressed size callers may ask for.
const MaxSize = 64 << 20

var (
	// ErrCorrupt is returned for compressed data that does not decode to the
	// size asked for.
	ErrCorrupt = errors.New("xpress: corrupt compressed data")

	errSize = errors.New("xpress: decompressed size out of range")
)

// DecompressHuffman decompresses LZ77+Huffman data (MS-XCA 2.2.4) to
// exactly size bytes: the compressed stream does not carry its own length,
// so the caller gives it (a PAC claims set's UncompressedClaimsSetSize).
func DecompressHuffman(src []byte, size int) ([]byte, error) {
	if size < 0 || size > MaxSize {
		return nil, errSize
	}

	out := make([]byte, 0, size)

	var (
		lens  [512]uint8
		table [1 << 15]uint16
	)

	pos := 0

	for len(out) < size {
		// A block: 512 code lengths, a nibble each (low nibble first), then
		// the codes of up to 65536 bytes of output.
		if pos+256+4 > len(src) {
			return nil, ErrCorrupt
		}

		for i := 0; i < 256; i++ {
			lens[2*i] = src[pos+i] & 15
			lens[2*i+1] = src[pos+i] >> 4
		}

		// The canonical code, by length then symbol: each symbol of length l
		// fills 2^(15-l) entries of the table read with the next 15 bits.
		next := 0

		for l := uint8(1); l <= 15; l++ {
			for sym := 0; sym < 512; sym++ {
				if lens[sym] != l {
					continue
				}

				span := 1 << (15 - l)
				if next+span > len(table) {
					return nil, ErrCorrupt
				}

				for k := 0; k < span; k++ {
					table[next+k] = uint16(sym)
				}

				next += span
			}
		}

		if next != len(table) {
			return nil, ErrCorrupt
		}

		pos += 256

		// The bits not yet used, at the top of 64 (MS-XCA keeps 32 and a
		// count of the extra bits read ahead, 16 at most).
		bits := (uint64(binary.LittleEndian.Uint16(src[pos:]))<<16 | uint64(binary.LittleEndian.Uint16(src[pos+2:]))) << 32
		extra := 16
		pos += 4

		refill := func() bool {
			if extra >= 0 {
				return true
			}

			if pos+2 > len(src) {
				return false
			}

			bits |= uint64(binary.LittleEndian.Uint16(src[pos:])) << uint(32-extra)
			extra += 16
			pos += 2

			return true
		}

		blockEnd := len(out) + 65536

		for len(out) < blockEnd && len(out) < size {
			sym := int(table[bits>>49])
			sl := int(lens[sym])

			bits <<= uint(sl)
			extra -= sl

			if !refill() {
				return nil, ErrCorrupt
			}

			if sym < 256 {
				out = append(out, byte(sym))
				continue
			}

			sym -= 256
			length := sym & 15
			offBits := sym >> 4

			if length == 15 {
				if pos+1 > len(src) {
					return nil, ErrCorrupt
				}

				length = int(src[pos])
				pos++

				if length == 255 {
					if pos+2 > len(src) {
						return nil, ErrCorrupt
					}

					length = int(binary.LittleEndian.Uint16(src[pos:]))
					pos += 2

					if length == 0 {
						if pos+4 > len(src) {
							return nil, ErrCorrupt
						}

						length = int(binary.LittleEndian.Uint32(src[pos:]))
						pos += 4
					}

					if length < 15 {
						return nil, ErrCorrupt
					}

					length -= 15
				}

				length += 15
			}

			length += 3

			offset := 1 << offBits
			if offBits > 0 {
				offset += int(bits >> uint(64-offBits))
				bits <<= uint(offBits)
				extra -= offBits

				if !refill() {
					return nil, ErrCorrupt
				}
			}

			if offset > len(out) || length > size-len(out) {
				return nil, ErrCorrupt
			}

			from := len(out) - offset
			for k := 0; k < length; k++ {
				out = append(out, out[from+k])
			}
		}
	}

	return out, nil
}

// Decompress decompresses plain LZ77 data (MS-XCA 2.4.4) to exactly size
// bytes.
func Decompress(src []byte, size int) ([]byte, error) {
	if size < 0 || size > MaxSize {
		return nil, errSize
	}

	out := make([]byte, 0, size)

	var flags uint32

	flagCount := 0
	pos := 0
	// Where the next half-byte of a match length comes from: the high
	// nibble of the byte at nibble, when nibble is set.
	nibble := -1

	for len(out) < size {
		if flagCount == 0 {
			if pos+4 > len(src) {
				return nil, ErrCorrupt
			}

			flags = binary.LittleEndian.Uint32(src[pos:])
			pos += 4
			flagCount = 32
		}

		flagCount--

		if flags&(1<<uint(flagCount)) == 0 {
			if pos >= len(src) {
				return nil, ErrCorrupt
			}

			out = append(out, src[pos])
			pos++

			continue
		}

		if pos+2 > len(src) {
			return nil, ErrCorrupt
		}

		v := int(binary.LittleEndian.Uint16(src[pos:]))
		pos += 2

		length := v & 7
		offset := v>>3 + 1

		if length == 7 {
			if nibble < 0 {
				if pos >= len(src) {
					return nil, ErrCorrupt
				}

				length = int(src[pos] & 15)
				nibble = pos
				pos++
			} else {
				length = int(src[nibble] >> 4)
				nibble = -1
			}

			if length == 15 {
				if pos >= len(src) {
					return nil, ErrCorrupt
				}

				length = int(src[pos])
				pos++

				if length == 255 {
					if pos+2 > len(src) {
						return nil, ErrCorrupt
					}

					length = int(binary.LittleEndian.Uint16(src[pos:]))
					pos += 2

					if length == 0 {
						if pos+4 > len(src) {
							return nil, ErrCorrupt
						}

						length = int(binary.LittleEndian.Uint32(src[pos:]))
						pos += 4
					}

					if length < 15+7 {
						return nil, ErrCorrupt
					}

					length -= 15 + 7
				}

				length += 15
			}

			length += 7
		}

		length += 3

		if offset > len(out) || length > size-len(out) {
			return nil, ErrCorrupt
		}

		from := len(out) - offset
		for k := 0; k < length; k++ {
			out = append(out, out[from+k])
		}
	}

	return out, nil
}
