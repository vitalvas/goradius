package goradius

import (
	"cmp"
	"fmt"
	"slices"
)

// tlvChildHeaderLength is the length of a TLV sub-attribute header (child type + child length).
const tlvChildHeaderLength = 2

// maxTLVChildValueLength is the maximum length of a single TLV sub-attribute value.
// The child length byte covers the header plus the value, so the value is bounded by 255-2.
const maxTLVChildValueLength = 253

// EncodeTLV encodes a map of child values into a TLV byte stream per the RADIUS TLV
// format (RFC 6929 Section 2.3). Each child is encoded as child_type(1) +
// child_length(1) + child_value(variable), where child_length covers the 2-byte header
// plus the value. Children are emitted in ascending child-ID order so output is stable.
//
// The parent attribute supplies the child definitions. Keys in values must match child
// attribute names; an unknown name or an oversized value is an error.
func EncodeTLV(parent *AttributeDefinition, values map[string]any) ([]byte, error) {
	if parent == nil {
		return nil, fmt.Errorf("nil parent attribute")
	}

	type encodedChild struct {
		id    uint32
		value []byte
	}

	encoded := make([]encodedChild, 0, len(values))
	for name, raw := range values {
		child, ok := parent.LookupChildByName(name)
		if !ok {
			return nil, fmt.Errorf("unknown TLV child %q for attribute %q", name, parent.Name)
		}

		// RFC 6929 Section 2.3 bounds TLV-Type to one octet (and reserves 254-255)
		if child.ID > 253 {
			return nil, fmt.Errorf("TLV child %q ID %d exceeds the one-octet TLV-Type range", name, child.ID)
		}

		childValue, err := EncodeValue(processEnumeratedValueFor(raw, child), child.DataType)
		if err != nil {
			return nil, fmt.Errorf("failed to encode TLV child %q: %w", name, err)
		}

		// RFC 6929 Section 2.3: TLV-Length is 3-255, so empty values cannot be carried
		if len(childValue) == 0 {
			return nil, fmt.Errorf("TLV child %q requires a non-empty value", name)
		}
		if len(childValue) > maxTLVChildValueLength {
			return nil, fmt.Errorf("TLV child %q value length %d exceeds maximum %d bytes", name, len(childValue), maxTLVChildValueLength)
		}

		encoded = append(encoded, encodedChild{id: child.ID, value: childValue})
	}

	// Stable, deterministic ordering by child ID.
	slices.SortFunc(encoded, func(a, b encodedChild) int { return cmp.Compare(a.id, b.id) })

	total := 0
	for _, e := range encoded {
		total += tlvChildHeaderLength + len(e.value)
	}

	out := make([]byte, 0, total)
	for _, e := range encoded {
		out = append(out, byte(e.id), byte(tlvChildHeaderLength+len(e.value)))
		out = append(out, e.value...)
	}

	return out, nil
}

// DecodeTLV decodes a TLV byte stream into a map keyed by child attribute name.
// Each known child is decoded to its native Go type via DecodeValue. Sub-attributes
// whose child ID is not defined on the parent are preserved as raw []byte keyed by
// their decimal child ID (for example "255"), so no data is silently dropped.
// A truncated sub-attribute (length byte pointing past the end) is an error.
func DecodeTLV(parent *AttributeDefinition, data []byte) (map[string]any, error) {
	if parent == nil {
		return nil, fmt.Errorf("nil parent attribute")
	}

	result := make(map[string]any)
	offset := 0
	for offset < len(data) {
		if offset+tlvChildHeaderLength > len(data) {
			return nil, fmt.Errorf("truncated TLV sub-attribute header at offset %d", offset)
		}

		childID := uint32(data[offset])
		childLen := int(data[offset+1])

		// RFC 6929 Section 2.3: TLV-Length must be 3-255, so a header-only
		// (empty value) sub-attribute is invalid
		if childLen < tlvChildHeaderLength+1 {
			return nil, fmt.Errorf("invalid TLV sub-attribute length %d at offset %d", childLen, offset)
		}

		if offset+childLen > len(data) {
			return nil, fmt.Errorf("TLV sub-attribute at offset %d extends beyond data (length %d, remaining %d)", offset, childLen, len(data)-offset)
		}

		childValue := data[offset+tlvChildHeaderLength : offset+childLen]

		if child, ok := parent.LookupChildByID(childID); ok {
			decoded, err := DecodeValue(childValue, child.DataType)
			if err != nil {
				return nil, fmt.Errorf("failed to decode TLV child %q: %w", child.Name, err)
			}
			result[child.Name] = decoded
		} else {
			raw := make([]byte, len(childValue))
			copy(raw, childValue)
			result[fmt.Sprintf("%d", childID)] = raw
		}

		offset += childLen
	}

	return result, nil
}

// processEnumeratedValueFor converts a string enumerated value to its integer code
// using the child's Values map. It mirrors Packet.processEnumeratedValue but is a free
// function so it can be reused by the TLV/struct encoders.
func processEnumeratedValueFor(value any, attrDef *AttributeDefinition) any {
	if len(attrDef.Values) == 0 {
		return value
	}
	if strValue, ok := value.(string); ok {
		if enumValue, exists := attrDef.Values[strValue]; exists {
			return enumValue
		}
	}
	return value
}
