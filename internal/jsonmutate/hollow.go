// Copyright 2026 Certen Protocol

package jsonmutate

// A hex member of a document carries a binary value (a transaction, a sequenced message, a signature, an account) that the verifier
// decodes with Accumulate's codec. The codec decodes a value with absent members without error (an absent URL is a nil URL, an absent
// body a nil body), so the crafted value that matters is not a truncated or flipped one, which the codec refuses, but a well-formed one
// with members missing: the value the codec accepts and the verifier then reads. For every hex member that decodes as one of the types
// below and re-encodes to exactly its bytes, HollowVariants returns the member with each exported field of the decoded value (at any
// depth, the first element of every list) set to its zero value, one at a time, re-encoded.

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Variant is one hollowed re-encoding: Name is the type and the field zeroed, Hex the member's new bytes.
type Variant struct{ Name, Hex string }

type binaryEncoder interface{ MarshalBinary() ([]byte, error) }

// hollowDecoders decode raw as one type; a decoder that fails, or whose value does not re-encode to raw, is not the member's type.
var hollowDecoders = []struct {
	name   string
	decode func(raw []byte) (binaryEncoder, error)
}{
	{"transaction", func(raw []byte) (binaryEncoder, error) {
		v := new(protocol.Transaction)
		return v, v.UnmarshalBinary(raw)
	}},
	{"sequenced", func(raw []byte) (binaryEncoder, error) {
		v := new(messaging.SequencedMessage)
		return v, v.UnmarshalBinary(raw)
	}},
	{"minor-root-record", func(raw []byte) (binaryEncoder, error) {
		v := new(api.MinorRootRecord)
		return v, v.UnmarshalBinary(raw)
	}},
	{"major-header-record", func(raw []byte) (binaryEncoder, error) {
		v := new(api.MajorHeaderRecord)
		return v, v.UnmarshalBinary(raw)
	}},
	{"receipt", func(raw []byte) (binaryEncoder, error) {
		v := new(merkle.Receipt)
		return v, v.UnmarshalBinary(raw)
	}},
	{"signature", func(raw []byte) (binaryEncoder, error) {
		v, err := protocol.UnmarshalSignature(raw)
		if err != nil {
			return nil, err
		}
		return v, nil
	}},
	{"account", func(raw []byte) (binaryEncoder, error) {
		v, err := protocol.UnmarshalAccount(raw)
		if err != nil {
			return nil, err
		}
		return v, nil
	}},
}

// fieldPaths lists the exported fields of v (a pointer to a struct, or an interface holding one) reachable through struct fields,
// pointers, interfaces and the first element of lists, to a depth of four. A path is a list of field names, "0" for a first element.
func fieldPaths(v reflect.Value, prefix []string, depth int, out *[][]string) {
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}
	if depth > 4 {
		return
	}
	switch v.Kind() {
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			p := append(append([]string{}, prefix...), f.Name)
			*out = append(*out, p)
			fieldPaths(v.Field(i), p, depth+1, out)
		}
	case reflect.Slice:
		if v.Len() > 0 && v.Type().Elem().Kind() != reflect.Uint8 {
			p := append(append([]string{}, prefix...), "0")
			fieldPaths(v.Index(0), p, depth+1, out)
		}
	}
}

// resolve returns the settable field a path names in v.
func resolve(v reflect.Value, path []string) (reflect.Value, bool) {
	for _, name := range path {
		for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
			if v.IsNil() {
				return reflect.Value{}, false
			}
			v = v.Elem()
		}
		switch v.Kind() {
		case reflect.Struct:
			v = v.FieldByName(name)
			if !v.IsValid() {
				return reflect.Value{}, false
			}
		case reflect.Slice:
			if name != "0" || v.Len() == 0 {
				return reflect.Value{}, false
			}
			v = v.Index(0)
		default:
			return reflect.Value{}, false
		}
	}
	return v, v.IsValid() && v.CanSet()
}

// HollowVariants returns, in a fixed order, the re-encodings of the value a hex member carries with one field at a time zeroed, each named
// by the type and the field. Nothing is returned for a member that is not one of the types.
func HollowVariants(h string) []Variant {
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw) < 4 {
		return nil
	}
	var out []Variant
	for _, d := range hollowDecoders {
		val, err := safeDecode(d.decode, raw)
		if err != nil || val == nil {
			continue
		}
		again, err := safeMarshal(val)
		if err != nil || hex.EncodeToString(again) != h {
			continue
		}
		var paths [][]string
		fieldPaths(reflect.ValueOf(val), nil, 0, &paths)
		for _, p := range paths {
			fresh, err := safeDecode(d.decode, raw)
			if err != nil {
				continue
			}
			rv := reflect.ValueOf(fresh)
			for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
				rv = rv.Elem()
			}
			f, ok := resolve(rv, p)
			if !ok {
				continue
			}
			f.Set(reflect.Zero(f.Type()))
			enc, err := safeMarshal(fresh)
			if err != nil || hex.EncodeToString(enc) == h {
				continue
			}
			out = append(out, Variant{Name: d.name + "." + strings.Join(p, "."), Hex: hex.EncodeToString(enc)})
		}
		return out // the first type that carries the member is its type
	}
	return nil
}

func safeDecode(f func([]byte) (binaryEncoder, error), raw []byte) (v binaryEncoder, err error) {
	defer func() {
		if r := recover(); r != nil {
			v, err = nil, fmt.Errorf("decode panics: %v", r)
		}
	}()
	return f(raw)
}

func safeMarshal(v binaryEncoder) (b []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			b, err = nil, fmt.Errorf("encode panics: %v", r)
		}
	}()
	return v.MarshalBinary()
}

var hollowCache sync.Map // hex string -> []Variant

// cachedHollowVariants is HollowVariants, remembered: the same transaction or signature is carried by many documents.
func cachedHollowVariants(h string) []Variant {
	if v, ok := hollowCache.Load(h); ok {
		return v.([]Variant)
	}
	v := HollowVariants(h)
	hollowCache.Store(h, v)
	return v
}
