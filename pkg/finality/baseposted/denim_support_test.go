// Copyright 2026 Certen Protocol

package baseposted

// denimPins gives the synthetic pins the post-Denim capability the embedded pins carry (batch type 0 only, 200 ms blocks, five per second).
func denimPins(bp *Pins) {
	bp.PostDenim = &PostDenim{BatchTypes: []uint8{0}, BlockIntervalMS: 200, BlocksPerSecond: 5,
		BaseTimePredeploy: [20]byte{0x42, 19: 0x30}, BaseTimeSelector: [4]byte{0x86, 0xbd, 0xf3, 0x94}}
}
