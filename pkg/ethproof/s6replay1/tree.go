// Copyright 2026 Certen Protocol

package s6replay1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// node is a JSON value that keeps object keys in document order, so a mutation changes exactly one thing and
// re-serialises every other byte as it was produced.
type node struct {
	kind byte // 'o' object, 'a' array, 's' string, 'n' number, 'b' bool, 'z' null
	keys []string
	vals []*node
	arr  []*node
	str  string
}

func parseTree(raw []byte) *node {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	n, err := parseNode(dec)
	if err != nil {
		panic(fmt.Sprintf("s6replay1: parse: %v", err))
	}
	if _, err := dec.Token(); err != io.EOF {
		panic("s6replay1: trailing data")
	}
	return n
}

func parseNode(dec *json.Decoder) (*node, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		if t == '{' {
			n := &node{kind: 'o'}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				child, err := parseNode(dec)
				if err != nil {
					return nil, err
				}
				n.keys = append(n.keys, kt.(string))
				n.vals = append(n.vals, child)
			}
			_, err := dec.Token()
			return n, err
		}
		n := &node{kind: 'a', arr: []*node{}}
		for dec.More() {
			child, err := parseNode(dec)
			if err != nil {
				return nil, err
			}
			n.arr = append(n.arr, child)
		}
		_, err := dec.Token()
		return n, err
	case string:
		return &node{kind: 's', str: t}, nil
	case json.Number:
		return &node{kind: 'n', str: t.String()}, nil
	case bool:
		if t {
			return &node{kind: 'b', str: "true"}, nil
		}
		return &node{kind: 'b', str: "false"}, nil
	}
	return &node{kind: 'z'}, nil
}

func (n *node) clone() *node {
	c := &node{kind: n.kind, str: n.str, keys: append([]string(nil), n.keys...)}
	for _, v := range n.vals {
		c.vals = append(c.vals, v.clone())
	}
	if n.kind == 'a' {
		c.arr = []*node{}
		for _, v := range n.arr {
			c.arr = append(c.arr, v.clone())
		}
	}
	return c
}

func (n *node) get(key string) *node {
	for i, k := range n.keys {
		if k == key {
			return n.vals[i]
		}
	}
	return nil
}

func (n *node) set(key string, v *node) {
	for i, k := range n.keys {
		if k == key {
			n.vals[i] = v
			return
		}
	}
	n.keys = append(n.keys, key)
	n.vals = append(n.vals, v)
}

func (n *node) remove(key string) {
	for i, k := range n.keys {
		if k == key {
			n.keys = append(n.keys[:i:i], n.keys[i+1:]...)
			n.vals = append(n.vals[:i:i], n.vals[i+1:]...)
			return
		}
	}
}

func (n *node) rename(from, to string) {
	for i, k := range n.keys {
		if k == from {
			n.keys[i] = to
		}
	}
}

// at walks a dotted path ("proof.after.accountProof.2").
func (n *node) at(path string) *node {
	cur := n
	for _, p := range strings.Split(path, ".") {
		if cur.kind == 'a' {
			var i int
			fmt.Sscanf(p, "%d", &i)
			cur = cur.arr[i]
			continue
		}
		cur = cur.get(p)
		if cur == nil {
			panic("s6replay1: no path " + path)
		}
	}
	return cur
}

func jstr(s string) *node { return &node{kind: 's', str: s} }
func jnum(s string) *node { return &node{kind: 'n', str: s} }
func jraw(kind byte) *node {
	if kind == 'a' {
		return &node{kind: 'a', arr: []*node{}}
	}
	return &node{kind: kind}
}

func (n *node) write(b *bytes.Buffer) {
	switch n.kind {
	case 'o':
		b.WriteByte('{')
		for i, k := range n.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			n.vals[i].write(b)
		}
		b.WriteByte('}')
	case 'a':
		b.WriteByte('[')
		for i, v := range n.arr {
			if i > 0 {
				b.WriteByte(',')
			}
			v.write(b)
		}
		b.WriteByte(']')
	case 's':
		writeString(b, n.str)
	case 'n', 'b':
		b.WriteString(n.str)
	default:
		b.WriteString("null")
	}
}

func writeString(b *bytes.Buffer, s string) {
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	b.Write(bytes.TrimRight(tmp.Bytes(), "\n"))
}

func (n *node) bytes() []byte {
	var b bytes.Buffer
	n.write(&b)
	return b.Bytes()
}
