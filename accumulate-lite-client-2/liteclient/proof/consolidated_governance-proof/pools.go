// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
)

// ObjectPools provides memory pools for frequent allocations
type ObjectPools struct {
	// JSON encoding/decoding pools
	jsonEncoderPool sync.Pool
	jsonDecoderPool sync.Pool

	// Buffer pools for string operations
	bufferPool     sync.Pool
	stringBuilders sync.Pool

	// Slice pools for common operations
	stringSlicePool    sync.Pool
	interfaceSlicePool sync.Pool
	mapPool           sync.Pool
}

// Global pools instance
var globalPools *ObjectPools
var poolsOnce sync.Once

// InitPools initializes the global object pools
func InitPools() *ObjectPools {
	poolsOnce.Do(func() {
		globalPools = &ObjectPools{
			jsonEncoderPool: sync.Pool{
				New: func() interface{} {
					buf := &bytes.Buffer{}
					return json.NewEncoder(buf)
				},
			},
			jsonDecoderPool: sync.Pool{
				New: func() interface{} {
					return json.NewDecoder(&bytes.Buffer{})
				},
			},
			bufferPool: sync.Pool{
				New: func() interface{} {
					return &bytes.Buffer{}
				},
			},
			stringBuilders: sync.Pool{
				New: func() interface{} {
					return &strings.Builder{}
				},
			},
			stringSlicePool: sync.Pool{
				New: func() interface{} {
					return make([]string, 0, 16) // Pre-allocate reasonable capacity
				},
			},
			interfaceSlicePool: sync.Pool{
				New: func() interface{} {
					return make([]interface{}, 0, 16)
				},
			},
			mapPool: sync.Pool{
				New: func() interface{} {
					return make(map[string]interface{}, 16)
				},
			},
		}
	})
	return globalPools
}

// GetPools returns the global pools instance
func GetPools() *ObjectPools {
	if globalPools == nil {
		return InitPools()
	}
	return globalPools
}

// JSON Encoding/Decoding with pooling

// JSONMarshalPooled marshals an object to JSON using pooled encoders
func JSONMarshalPooled(v interface{}) ([]byte, error) {
	pools := GetPools()

	buf := pools.GetBuffer()
	defer pools.PutBuffer(buf)

	encoder := json.NewEncoder(buf)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}

	// Remove the trailing newline that Encode adds
	result := buf.Bytes()
	if len(result) > 0 && result[len(result)-1] == '\n' {
		result = result[:len(result)-1]
	}

	// Return a copy since we're returning the buffer to the pool
	output := make([]byte, len(result))
	copy(output, result)
	return output, nil
}

// JSONUnmarshalPooled unmarshals JSON data using pooled decoders
func JSONUnmarshalPooled(data []byte, v interface{}) error {
	pools := GetPools()

	buf := pools.GetBuffer()
	defer pools.PutBuffer(buf)

	buf.Write(data)
	decoder := json.NewDecoder(buf)
	return decoder.Decode(v)
}

// Buffer management

// GetBuffer gets a buffer from the pool
func (p *ObjectPools) GetBuffer() *bytes.Buffer {
	buf := p.bufferPool.Get().(*bytes.Buffer)
	buf.Reset() // Ensure it's clean
	return buf
}

// PutBuffer returns a buffer to the pool
func (p *ObjectPools) PutBuffer(buf *bytes.Buffer) {
	if buf.Cap() > 64*1024 { // Don't pool overly large buffers
		return
	}
	p.bufferPool.Put(buf)
}

// String builder management

// GetStringBuilder gets a string builder from the pool
func (p *ObjectPools) GetStringBuilder() *strings.Builder {
	sb := p.stringBuilders.Get().(*strings.Builder)
	sb.Reset() // Ensure it's clean
	return sb
}

// PutStringBuilder returns a string builder to the pool
func (p *ObjectPools) PutStringBuilder(sb *strings.Builder) {
	if sb.Cap() > 64*1024 { // Don't pool overly large builders
		return
	}
	p.stringBuilders.Put(sb)
}

// Slice management

// GetStringSlice gets a string slice from the pool
func (p *ObjectPools) GetStringSlice() []string {
	slice := p.stringSlicePool.Get().([]string)
	return slice[:0] // Reset length but keep capacity
}

// PutStringSlice returns a string slice to the pool
func (p *ObjectPools) PutStringSlice(slice []string) {
	if cap(slice) > 1024 { // Don't pool overly large slices
		return
	}
	p.stringSlicePool.Put(slice)
}

// GetInterfaceSlice gets an interface slice from the pool
func (p *ObjectPools) GetInterfaceSlice() []interface{} {
	slice := p.interfaceSlicePool.Get().([]interface{})
	return slice[:0] // Reset length but keep capacity
}

// PutInterfaceSlice returns an interface slice to the pool
func (p *ObjectPools) PutInterfaceSlice(slice []interface{}) {
	if cap(slice) > 1024 { // Don't pool overly large slices
		return
	}
	p.interfaceSlicePool.Put(slice)
}

// Map management

// GetMap gets a map from the pool
func (p *ObjectPools) GetMap() map[string]interface{} {
	m := p.mapPool.Get().(map[string]interface{})
	// Clear the map
	for k := range m {
		delete(m, k)
	}
	return m
}

// PutMap returns a map to the pool
func (p *ObjectPools) PutMap(m map[string]interface{}) {
	if len(m) > 256 { // Don't pool overly large maps
		return
	}
	p.mapPool.Put(m)
}

// Convenience functions for string building

// BuildStringPooled builds a string using a pooled string builder
func BuildStringPooled(fn func(*strings.Builder)) string {
	pools := GetPools()
	sb := pools.GetStringBuilder()
	defer pools.PutStringBuilder(sb)

	fn(sb)
	return sb.String()
}

// ConcatStringsPooled concatenates strings using a pooled string builder
func ConcatStringsPooled(strs ...string) string {
	if len(strs) == 0 {
		return ""
	}
	if len(strs) == 1 {
		return strs[0]
	}

	return BuildStringPooled(func(sb *strings.Builder) {
		for _, s := range strs {
			sb.WriteString(s)
		}
	})
}