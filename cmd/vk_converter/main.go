package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
)

// BN254 field modulus
var fieldModulus, _ = new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)
var halfFieldModulus = new(big.Int).Div(fieldModulus, big.NewInt(2))

// VK JSON structure matching the export format
type VKExport struct {
	Alpha1 [2]json.Number   `json:"alpha1"`
	Beta2  [2][2]json.Number `json:"beta2"`
	Gamma2 [2][2]json.Number `json:"gamma2"`
	Delta2 [2][2]json.Number `json:"delta2"`
	IC     [][2]json.Number  `json:"ic"`
}

func bigIntToLE32(v *big.Int) [32]byte {
	var result [32]byte
	b := v.Bytes() // big-endian
	// Copy to result in reverse (little-endian)
	for i, byt := range b {
		result[len(b)-1-i] = byt
	}
	return result
}

func isNegativeY(y *big.Int) bool {
	return y.Cmp(halfFieldModulus) > 0
}

// Encode G1 point in Arkworks compressed format (32 bytes)
func encodeG1Compressed(xStr, yStr string) []byte {
	x, _ := new(big.Int).SetString(xStr, 10)
	y, _ := new(big.Int).SetString(yStr, 10)

	result := bigIntToLE32(x)

	// Set flags in top 2 bits of last byte (byte[31] in LE)
	if x.Sign() == 0 && y.Sign() == 0 {
		result[31] |= 0x40 // point at infinity
	} else if isNegativeY(y) {
		result[31] |= 0x80 // negative Y
	}
	// else: positive Y, flag = 0x00

	return result[:]
}

// Encode G2 point in Arkworks compressed format (64 bytes)
// G2 x-coordinate is Fq2 = (c0, c1), Y parity uses c1 then c0
func encodeG2Compressed(x0Str, x1Str, y0Str, y1Str string) []byte {
	x0, _ := new(big.Int).SetString(x0Str, 10) // c0
	x1, _ := new(big.Int).SetString(x1Str, 10) // c1
	y0, _ := new(big.Int).SetString(y0Str, 10) // c0
	y1, _ := new(big.Int).SetString(y1Str, 10) // c1

	c0 := bigIntToLE32(x0)
	c1 := bigIntToLE32(x1)

	// Arkworks format: c0 || c1 (each 32 bytes LE)
	var result [64]byte
	copy(result[0:32], c0[:])
	copy(result[32:64], c1[:])

	// For Fq2, Y parity: check if y1 > half_p, or if y1 == 0 then check y0 > half_p
	isNeg := false
	if y1.Sign() != 0 {
		isNeg = y1.Cmp(halfFieldModulus) > 0
	} else {
		isNeg = y0.Cmp(halfFieldModulus) > 0
	}

	if x0.Sign() == 0 && x1.Sign() == 0 && y0.Sign() == 0 && y1.Sign() == 0 {
		result[63] |= 0x40 // point at infinity
	} else if isNeg {
		result[63] |= 0x80 // negative Y
	}

	return result[:]
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <verification_key.json>\n", os.Args[0])
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	var vk VKExport
	if err := json.Unmarshal(data, &vk); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	var arkVK []byte

	// 1. alpha_g1 (32 bytes)
	arkVK = append(arkVK, encodeG1Compressed(string(vk.Alpha1[0]), string(vk.Alpha1[1]))...)

	// 2. beta_g2 (64 bytes)
	arkVK = append(arkVK, encodeG2Compressed(
		string(vk.Beta2[0][0]), string(vk.Beta2[0][1]),
		string(vk.Beta2[1][0]), string(vk.Beta2[1][1]),
	)...)

	// 3. gamma_g2 (64 bytes)
	arkVK = append(arkVK, encodeG2Compressed(
		string(vk.Gamma2[0][0]), string(vk.Gamma2[0][1]),
		string(vk.Gamma2[1][0]), string(vk.Gamma2[1][1]),
	)...)

	// 4. delta_g2 (64 bytes)
	arkVK = append(arkVK, encodeG2Compressed(
		string(vk.Delta2[0][0]), string(vk.Delta2[0][1]),
		string(vk.Delta2[1][0]), string(vk.Delta2[1][1]),
	)...)

	// 5. gamma_abc_g1 length prefix (8 bytes, u64 LE)
	numIC := uint64(len(vk.IC))
	lenBytes := make([]byte, 8)
	lenBytes[0] = byte(numIC)
	lenBytes[1] = byte(numIC >> 8)
	lenBytes[2] = byte(numIC >> 16)
	lenBytes[3] = byte(numIC >> 24)
	lenBytes[4] = byte(numIC >> 32)
	lenBytes[5] = byte(numIC >> 40)
	lenBytes[6] = byte(numIC >> 48)
	lenBytes[7] = byte(numIC >> 56)
	arkVK = append(arkVK, lenBytes...)

	// 6. IC/gamma_abc_g1 points (each 32 bytes)
	for _, ic := range vk.IC {
		arkVK = append(arkVK, encodeG1Compressed(string(ic[0]), string(ic[1]))...)
	}

	fmt.Fprintf(os.Stderr, "Arkworks VK size: %d bytes (expected 392 for 4 public inputs)\n", len(arkVK))
	fmt.Fprintf(os.Stderr, "Number of IC points: %d\n", len(vk.IC))
	fmt.Println(hex.EncodeToString(arkVK))
}
