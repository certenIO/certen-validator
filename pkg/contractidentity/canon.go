// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strconv"
)

// Canonical renders v in the cross-language canonical form that Go and TypeScript compare on every vector (V2_SPEC_S7 s.6, extended to
// lists of objects): JSON with object keys sorted bytewise and no whitespace; EVERY integer of ANY width and signedness (and *big.Int) as
// a decimal STRING; every byte string and fixed byte array ([]byte, [N]byte, any named byte slice) as "0x" + lowercase hex ("0x" for the
// empty string); strings JSON-escaped without HTML escaping; booleans and null as literals; lists in the order given.
//
// Unlike the S7 encoder there is no fall-back rendering: a value of any other kind (a float, a struct, a channel, ...) is an error, so a
// state or a report can never carry a value whose cross-language form is undefined.
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := canonWrite(&b, reflect.ValueOf(v)); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func canonString(b *bytes.Buffer, s string) {
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	b.Write(bytes.TrimRight(tmp.Bytes(), "\n"))
}

var bigIntType = reflect.TypeOf((*big.Int)(nil))

func canonWrite(b *bytes.Buffer, rv reflect.Value) error {
	if !rv.IsValid() {
		b.WriteString("null")
		return nil
	}
	if rv.Type() == bigIntType {
		if rv.IsNil() {
			b.WriteString("null")
			return nil
		}
		canonString(b, rv.Interface().(*big.Int).String())
		return nil
	}
	switch rv.Kind() {
	case reflect.Interface, reflect.Pointer:
		if rv.IsNil() {
			b.WriteString("null")
			return nil
		}
		return canonWrite(b, rv.Elem())
	case reflect.Bool:
		b.WriteString(strconv.FormatBool(rv.Bool()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		canonString(b, strconv.FormatInt(rv.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		canonString(b, strconv.FormatUint(rv.Uint(), 10))
	case reflect.String:
		canonString(b, rv.String())
	case reflect.Array, reflect.Slice:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			raw := make([]byte, rv.Len())
			reflect.Copy(reflect.ValueOf(raw), rv)
			canonString(b, "0x"+hex.EncodeToString(raw))
			return nil
		}
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			b.WriteString("[]")
			return nil
		}
		b.WriteByte('[')
		for i := 0; i < rv.Len(); i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := canonWrite(b, rv.Index(i)); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return fmt.Errorf("contractidentity: canonical form: map key kind %s is not a string", rv.Type().Key().Kind())
		}
		keys := rv.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			canonString(b, k.String())
			b.WriteByte(':')
			if err := canonWrite(b, rv.MapIndex(k)); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("contractidentity: canonical form: unsupported value kind %s (%s)", rv.Kind(), rv.Type())
	}
	return nil
}
