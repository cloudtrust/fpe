// See U.S. National Institute of Standards and Technology (NIST)
// Special Publication 800-38G, ``Recommendation for Block Cipher
// Modes of Operation: Methods for Format-Preserving Encryption''
// 2016 Edition, pp. 12-13.
package fpe

import (
	"math/big"
	"encoding/binary"
	"math"
)

// numRadix takes a number radix and a numeral string x. It returns the
// number that the numeral string x represents in base radix when the numerals
// are valued in decreasing order of significance.
func numRadix(x []uint16, radix uint32) (*big.Int) {
	var out = big.NewInt(0)
	var l = len(x)
	var r = big.NewInt(int64(radix))

	for i := 0; i < l; i++ {
		out.Mul(out, r)
		out.Add(out, big.NewInt(int64(x[i])))
	}

	return out
}

// num takes a bit string x. It returns the integer that the bit string x
// represents when the bits are valued in decreasing order of significance.
func num(x []byte) (*big.Int) {
	var out = big.NewInt(0)
	return out.SetBytes(x)
}

// strMRadix takes an integer m, an integer radix and an integer x (less than radix^m).
// It returns the representation of x as a string of m numerals in base radix, in
// decreasing order of significance.
func strMRadix(radix, m uint32, x *big.Int) ([]uint16) {
	var out = make([]uint16, m)
	var bigRadix = big.NewInt(int64(radix))
	// x must be in [0..radix^[
	var maxX = big.NewInt(0).Exp(bigRadix, big.NewInt(int64(m)), nil)
	if x.Cmp(big.NewInt(0)) == -1 || x.Cmp(maxX) != -1 {
		panic("strMRadix: x must be in [0..radix^m[.")
	}

	var temp big.Int
	var i uint32
	for i = 0; i < m; i++ {
		temp.Mod(x, bigRadix)
		out[m-i-1] = uint16(temp.Uint64())
		x.Div(x, bigRadix)
	}

	return out
}

// rev takes a numeral string x and returns the numeral string that
// consists of the numerals of x in reverse order.
func rev(x []uint16) ([]uint16) {
	var l = len(x)
	var out = make([]uint16, l)

	for i := 0; i < l; i++ {
		out[i] = x[l-i-1]
	}

	return out
}

// revB takes a byte string x returns the byte string that consists
// of the bytes of x in reverse order.
func RevB(x []byte) ([]byte) {
	var l = len(x)
	var out = make([]byte, l)

	for i := 0; i < l; i++ {
		out[i] = x[l-i-1]
	}

	return out
}

// getAsBBytes takes an integer b and a an integer x in[0..256^b[. It returns the
// representation of x as a string of b bytes.
func getAsBBytes(x *big.Int, b uint64) ([]byte) {
	var maxX = big.NewInt(256)
	maxX.Exp(maxX, big.NewInt(int64(b)), nil)
	if x.Cmp(big.NewInt(0)) == -1 || x.Cmp(maxX) != -1 {
		panic("getAsBBytes: x must be in [0..256^b[.")
	}

	var out = make([]byte, b)
	var numRadixAsBytes = x.Bytes()
	var l = uint64(len(numRadixAsBytes))
	copy(out[b-l:], numRadixAsBytes)
	return out
}

// isNumeralStringValid takes a numeral string x and an integer radix. It returns true if
// the numeral string is valid, false otherwise.
func isNumeralStringValid(x []uint16, radix uint32) (bool) {
	for i := 0; i < len(x); i++ {
		if uint32(x[i]) >= radix {
			return false
		}
	}
	return true
}

// NumeralStringToBytes takes a string of numerals, each of them is
// in [0..2^16[. It returns the representation of numeralString as
// a byte array, where each numeral is stored using 2 bytes.
func NumeralStringToBytes(numeralString []uint16) ([]byte) {
	var l = len(numeralString)
	var out = make([]byte, 2 * l)

	for i := 0; i < l; i++ {
		binary.BigEndian.PutUint16(out[2*i:2*(i+1)], numeralString[i])
	}

	return out
}

// BytesToNumeralString takes a byte array and returns its representation
// as a string of numerals.
func BytesToNumeralString(bytes []byte) ([]uint16) {
	var size = int(math.Ceil(float64(len(bytes) / 2)))
	var out = make([]uint16, size)
	var l = len(out)

	for i := 0; i < l; i++ {
		out[i] = binary.BigEndian.Uint16(bytes[2*i:2*(i+1)])
	}

	return out
}

//This function is taken from the go crypto package (in xor.go)
func xorBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}
