// Copyright 2026 Certen Protocol

package arbposted

// zeroheavyDecode is nitro@ccc5c82 zeroheavy.ZeroheavyDecoder over a byte slice, read to its end or to max+1 bytes. The format
// (legacy calldata gas saving) writes a zero byte as two bits, 0x01 as eight and a byte below 0x80 as nine, and a byte from 0x80 as
// nine; the decoder is lenient by construction: bits left over at the end (the encoder's "0 then 1s" padding) are never emitted, so
// every input decodes to something. exceeded is true when the output would pass max bytes.
func zeroheavyDecode(in []byte, max int) (out []byte, exceeded bool) {
	d := &zhDecoder{src: in}
	for {
		b, ok := d.readOne()
		if !ok {
			return out, false
		}
		if len(out) == max {
			return nil, true
		}
		out = append(out, b)
	}
}

type zhDecoder struct {
	src             []byte
	pos             int
	buffer          []bool
	eofAfterBuffer  bool
	deferredZero    bool
	numDeferredOnes uint
}

func (d *zhDecoder) readOne() (byte, bool) {
	var ret byte
	for i := 0; i < 8; i++ {
		b, ok := d.nextBit()
		if !ok {
			return 0, false
		}
		ret <<= 1
		if b {
			ret |= 1
		}
	}
	return ret, true
}

func (d *zhDecoder) pushBit(b bool) {
	if d.deferredZero {
		if b {
			d.numDeferredOnes++
			return
		}
		d.buffer = append(d.buffer, false)
		for d.numDeferredOnes > 0 {
			d.buffer = append(d.buffer, true)
			d.numDeferredOnes--
		}
		return
	}
	if b {
		d.buffer = append(d.buffer, true)
	} else {
		d.deferredZero = true
	}
}

func (d *zhDecoder) push7Bits(b byte) {
	for i := 0; i < 7; i++ {
		d.pushBit(b&(1<<(6-i)) != 0)
	}
}

func (d *zhDecoder) nextBit() (bool, bool) {
	for len(d.buffer) == 0 {
		if d.eofAfterBuffer {
			return false, false
		}
		d.eofAfterBuffer = d.refill()
	}
	ret := d.buffer[0]
	d.buffer = d.buffer[1:]
	return ret, true
}

// refill reads one source byte into the bit buffer and reports whether the source is at its end.
func (d *zhDecoder) refill() bool {
	if d.pos >= len(d.src) {
		return true
	}
	b := d.src[d.pos]
	d.pos++
	switch {
	case b == 0:
		d.pushBit(false)
		d.pushBit(false)
	case b == 1:
		d.pushBit(false)
		d.pushBit(true)
		for i := 0; i < 6; i++ {
			d.pushBit(false)
		}
	case b < 0x80:
		d.pushBit(false)
		d.pushBit(true)
		d.push7Bits(b)
	default:
		d.pushBit(true)
		d.push7Bits(b & 0x7f)
	}
	return false
}
