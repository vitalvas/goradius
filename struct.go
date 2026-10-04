package goradius

import (
	"fmt"
)

// fixedWidthFor returns the fixed encoded width in bytes for a scalar data type,
// or (0, false) if the type is variable-width. Struct members use these widths to
// lay out fields sequentially without per-field length headers.
func fixedWidthFor(dataType DataType) (int, bool) {
	switch dataType {
	case DataTypeByte:
		return 1, true
	case DataTypeShort:
		return 2, true
	case DataTypeInteger, DataTypeIPAddr, DataTypeDate, DataTypeSigned, DataTypeTimeDelta:
		return 4, true
	case DataTypeInteger64:
		return 8, true
	case DataTypeIPv6Addr:
		return 16, true
	case DataTypeIfID:
		return 8, true
	default:
		return 0, false
	}
}

// structMemberWidth returns the encoded width for a struct member. Fixed-width scalar
// types use their natural width; variable-width types (string, octets) require an
// explicit Size hint on the child definition.
func structMemberWidth(child *AttributeDefinition) (int, error) {
	if w, ok := fixedWidthFor(child.DataType); ok {
		return w, nil
	}
	if child.Size > 0 {
		return child.Size, nil
	}
	return 0, fmt.Errorf("struct member %q of type %q requires a Size hint", child.Name, child.DataType)
}

// isTrailingVariableMember reports whether a struct member is a variable-width
// type (string or octets) with no fixed Size. Such a member is only valid as
// the final member of a struct, where it consumes the remaining bytes. This
// matches layouts such as RFC 5580 Location-Information, whose trailing Method
// field is an open-ended string.
func isTrailingVariableMember(child *AttributeDefinition) bool {
	if _, fixed := fixedWidthFor(child.DataType); fixed {
		return false
	}
	if child.Size > 0 {
		return false
	}
	return child.DataType == DataTypeString || child.DataType == DataTypeOctets
}

// EncodeStruct encodes a map of child values into a fixed-layout struct byte stream.
// Members are written sequentially in the order their definitions appear in parent.Children,
// with no per-field type/length header. Every member must be supplied; fixed-width scalar
// types determine their own width, while sized variable-width members (string, octets) are
// zero-padded to their declared Size. A value longer than its declared Size is an error.
// A final string/octets member with no Size is a trailing member: it is written at its
// natural length and consumes the remainder of the struct.
//
// Consecutive bit[N] members are packed MSB-first and must fill whole octets. A
// trailing union member is encoded as a nested struct selected by its key.
func EncodeStruct(parent *AttributeDefinition, values map[string]any) ([]byte, error) {
	if parent == nil {
		return nil, fmt.Errorf("nil parent attribute")
	}

	out := make([]byte, 0, 16)
	var bits bitWriter

	for i, child := range parent.Children {
		if child.DataType == DataTypeBits {
			v, err := memberUint(values, parent, child)
			if err != nil {
				return nil, err
			}
			if err := bits.write(child.Bits, v); err != nil {
				return nil, fmt.Errorf("struct member %q: %w", child.Name, err)
			}
			if bits.aligned() {
				out = append(out, bits.flush()...)
			}
			continue
		}
		if !bits.aligned() {
			return nil, fmt.Errorf("struct %q bit members before %q do not fill whole octets", parent.Name, child.Name)
		}

		raw, ok := values[child.Name]
		if !ok {
			return nil, fmt.Errorf("struct %q missing member %q", parent.Name, child.Name)
		}

		if child.DataType == DataTypeUnion {
			if i != len(parent.Children)-1 {
				return nil, fmt.Errorf("union member %q must be the final member of struct %q", child.Name, parent.Name)
			}
			keyVal, err := unionKeyValue(values, parent, child)
			if err != nil {
				return nil, err
			}
			variant := unionVariant(child, keyVal)
			if variant == nil {
				return nil, fmt.Errorf("union member %q has no variant for key %d", child.Name, keyVal)
			}
			sub, ok := raw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("union member %q requires a map[string]any value", child.Name)
			}
			encoded, err := EncodeStruct(variant, sub)
			if err != nil {
				return nil, fmt.Errorf("union member %q: %w", child.Name, err)
			}
			out = append(out, encoded...)
			break
		}

		encoded, err := EncodeValue(processEnumeratedValueFor(raw, child), child.DataType)
		if err != nil {
			return nil, fmt.Errorf("failed to encode struct member %q: %w", child.Name, err)
		}

		if isTrailingVariableMember(child) {
			if i != len(parent.Children)-1 {
				return nil, fmt.Errorf("struct member %q of type %q without a Size must be the final member", child.Name, child.DataType)
			}
			out = append(out, encoded...)
			break
		}

		width, err := structMemberWidth(child)
		if err != nil {
			return nil, err
		}
		if _, fixed := fixedWidthFor(child.DataType); fixed {
			if len(encoded) != width {
				return nil, fmt.Errorf("struct member %q encoded to %d bytes, expected %d", child.Name, len(encoded), width)
			}
		} else if len(encoded) > width {
			// Variable-width member: zero-padded, but silent truncation loses data
			return nil, fmt.Errorf("struct member %q encoded to %d bytes, exceeds declared size %d", child.Name, len(encoded), width)
		}
		field := make([]byte, width)
		copy(field, encoded)
		out = append(out, field...)
	}

	if !bits.aligned() {
		return nil, fmt.Errorf("struct %q trailing bit members do not fill whole octets", parent.Name)
	}

	return out, nil
}

// DecodeStruct decodes a fixed-layout struct byte stream into a map keyed by member name.
// Each member is read using its fixed width or declared Size, in definition order.
// Trailing bytes beyond the declared layout, or a stream too short for the layout, are errors.
func DecodeStruct(parent *AttributeDefinition, data []byte) (map[string]any, error) {
	if parent == nil {
		return nil, fmt.Errorf("nil parent attribute")
	}

	result := make(map[string]any)
	offset := 0
	var bits bitReader

	for i, child := range parent.Children {
		if child.DataType == DataTypeBits {
			if bits.empty() {
				if offset >= len(data) {
					return nil, fmt.Errorf("struct %q truncated at bit member %q", parent.Name, child.Name)
				}
				// A run of bit members consumes whole octets; load as many as
				// the run needs. Load one octet at a time as bits are read.
			}
			v, consumed, err := bits.read(child.Bits, data[offset:])
			if err != nil {
				return nil, fmt.Errorf("struct %q member %q: %w", parent.Name, child.Name, err)
			}
			offset += consumed
			result[child.Name] = v
			continue
		}
		if !bits.aligned() {
			return nil, fmt.Errorf("struct %q bit members before %q do not fill whole octets", parent.Name, child.Name)
		}

		if child.DataType == DataTypeUnion {
			if i != len(parent.Children)-1 {
				return nil, fmt.Errorf("union member %q must be the final member of struct %q", child.Name, parent.Name)
			}
			keyVal, err := unionKeyFromResult(result, child)
			if err != nil {
				return nil, err
			}
			variant := unionVariant(child, keyVal)
			if variant == nil {
				return nil, fmt.Errorf("union member %q has no variant for key %d", child.Name, keyVal)
			}
			sub, err := DecodeStruct(variant, data[offset:])
			if err != nil {
				return nil, fmt.Errorf("union member %q: %w", child.Name, err)
			}
			result[child.Name] = sub
			offset = len(data)
			break
		}

		// A final string/octets member with no Size consumes the remaining bytes.
		if isTrailingVariableMember(child) {
			if i != len(parent.Children)-1 {
				return nil, fmt.Errorf("struct member %q of type %q without a Size must be the final member", child.Name, child.DataType)
			}
			decoded, err := DecodeValue(data[offset:], child.DataType)
			if err != nil {
				return nil, fmt.Errorf("failed to decode struct member %q: %w", child.Name, err)
			}
			result[child.Name] = decoded
			offset = len(data)
			break
		}

		width, err := structMemberWidth(child)
		if err != nil {
			return nil, err
		}

		if offset+width > len(data) {
			return nil, fmt.Errorf("struct %q truncated: member %q needs %d bytes at offset %d, have %d", parent.Name, child.Name, width, offset, len(data)-offset)
		}

		field := data[offset : offset+width]
		decoded, err := DecodeValue(field, child.DataType)
		if err != nil {
			return nil, fmt.Errorf("failed to decode struct member %q: %w", child.Name, err)
		}
		result[child.Name] = decoded
		offset += width
	}

	if !bits.aligned() {
		return nil, fmt.Errorf("struct %q trailing bit members do not fill whole octets", parent.Name)
	}

	if offset != len(data) {
		return nil, fmt.Errorf("struct %q has %d trailing bytes after layout", parent.Name, len(data)-offset)
	}

	return result, nil
}

// bitWriter accumulates MSB-first bit fields and emits whole octets.
type bitWriter struct {
	acc  uint64
	nset int // number of bits currently buffered
}

func (w *bitWriter) write(width int, v uint64) error {
	if width <= 0 || width > 32 {
		return fmt.Errorf("invalid bit width %d", width)
	}
	if width < 64 && v >= (uint64(1)<<width) {
		return fmt.Errorf("value %d does not fit in %d bits", v, width)
	}
	w.acc = (w.acc << width) | v
	w.nset += width
	return nil
}

func (w *bitWriter) aligned() bool { return w.nset%8 == 0 }

// flush returns the buffered whole octets and resets the buffer. It must only be
// called when aligned.
func (w *bitWriter) flush() []byte {
	n := w.nset / 8
	out := make([]byte, n)
	for i := n - 1; i >= 0; i-- {
		out[i] = byte(w.acc)
		w.acc >>= 8
	}
	w.acc = 0
	w.nset = 0
	return out
}

// bitReader reads MSB-first bit fields from a byte stream, consuming whole
// octets as runs complete.
type bitReader struct {
	acc  uint64
	navl int // bits currently available in acc
	used int // bits consumed from the current run (for alignment checks)
}

func (r *bitReader) empty() bool { return r.navl == 0 }

func (r *bitReader) aligned() bool { return r.used%8 == 0 }

// read returns the next width-bit value, loading octets from data as needed.
// consumed is the number of octets taken from data on this call.
func (r *bitReader) read(width int, data []byte) (uint64, int, error) {
	if width <= 0 || width > 32 {
		return 0, 0, fmt.Errorf("invalid bit width %d", width)
	}
	consumed := 0
	for r.navl < width {
		if len(data) == consumed {
			return 0, 0, fmt.Errorf("not enough data for %d-bit field", width)
		}
		r.acc = (r.acc << 8) | uint64(data[consumed])
		r.navl += 8
		consumed++
	}
	shift := r.navl - width
	v := (r.acc >> shift) & ((uint64(1) << width) - 1)
	r.navl -= width
	r.acc &= (uint64(1) << r.navl) - 1
	r.used += width
	if r.used%8 == 0 {
		r.used = 0
	}
	return v, consumed, nil
}

// memberUint fetches a struct member value as a uint64 for bit encoding,
// applying enumerated-name resolution.
func memberUint(values map[string]any, parent, child *AttributeDefinition) (uint64, error) {
	raw, ok := values[child.Name]
	if !ok {
		return 0, fmt.Errorf("struct %q missing member %q", parent.Name, child.Name)
	}
	raw = processEnumeratedValueFor(raw, child)
	switch n := raw.(type) {
	case uint64:
		return n, nil
	case uint32:
		return uint64(n), nil
	case uint8:
		return uint64(n), nil
	case uint16:
		return uint64(n), nil
	case int:
		if n < 0 {
			return 0, fmt.Errorf("struct member %q negative value %d", child.Name, n)
		}
		return uint64(n), nil
	default:
		return 0, fmt.Errorf("struct member %q expected an integer bit value", child.Name)
	}
}

// unionVariant returns the variant definition of a union member matching the
// key value, or nil.
func unionVariant(union *AttributeDefinition, key uint64) *AttributeDefinition {
	for _, v := range union.Children {
		if uint64(v.ID) == key {
			return v
		}
	}
	return nil
}

// unionKeyValue reads the union's key member from the supplied value map.
func unionKeyValue(values map[string]any, parent, union *AttributeDefinition) (uint64, error) {
	keyChild := findChild(parent, union.UnionKey)
	if keyChild == nil {
		return 0, fmt.Errorf("union member %q references unknown key %q", union.Name, union.UnionKey)
	}
	return memberUint(values, parent, keyChild)
}

// unionKeyFromResult reads the union's key member from an already-decoded result map.
func unionKeyFromResult(result map[string]any, union *AttributeDefinition) (uint64, error) {
	v, ok := result[union.UnionKey]
	if !ok {
		return 0, fmt.Errorf("union member %q key %q not decoded", union.Name, union.UnionKey)
	}
	switch n := v.(type) {
	case uint8:
		return uint64(n), nil
	case uint16:
		return uint64(n), nil
	case uint32:
		return uint64(n), nil
	case uint64:
		return n, nil
	default:
		return 0, fmt.Errorf("union key %q is not an integer", union.UnionKey)
	}
}

func findChild(parent *AttributeDefinition, name string) *AttributeDefinition {
	for _, c := range parent.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}
