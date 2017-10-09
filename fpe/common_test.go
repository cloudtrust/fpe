package fpe

import (
	"testing"
	"bytes"
	"math/big"
	"math/rand"
	"time"
)
const (
	nbrTests = 1000
)

func TestNumRadix(t *testing.T) {
	var x = []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	var radix uint32 = 20
	var expected = big.NewInt(28365650969)
	var result = numRadix(x, radix)

	if result.Cmp(expected) != 0 {
		t.Errorf("%s:\nhave %s\nwant %s", t.Name(), result.String(), expected.String())
	}
}

func TestNum(t *testing.T) {
	var x = []byte{0x52, 0x1f, 0x6e, 0x4a, 0x88, 0xb7, 0xe0, 0x30}
	var expected = big.NewInt(5917569701788508208)
	var result = num(x)

	if result.Cmp(expected) != 0 {
		t.Errorf("%s:\nhave %s\nwant %s", t.Name(), result.String(), expected.String())
	}
}

func TestStrMRadix(t *testing.T) {
	var x = big.NewInt(123456789)
	var expected = []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	var result = strMRadix(10, 10, x)

	if !compareNumeralString(result, expected) {
		t.Errorf("%s:\nhave %d\nwant %d", t.Name(), result, expected)
	}
	// Test corner cases
	var radix = uint32(maxRadixFF1)
	var m = uint32(10)
	x = big.NewInt(int64(radix))
	x.Exp(x, big.NewInt(int64(m)), nil)
	x.Sub(x, big.NewInt(1))
	result = strMRadix(radix, m, x)
	var l = uint32(len(result))
	if l != m {
		t.Errorf("%s: output is not %d bytes", t.Name(), m)
	}
	for i := 0; i < len(result); i++ {
		if result[i] != maxRadixFF1-1 {
			t.Errorf("%s:\nhave %x", t.Name(), result)
			break
		}
	}
}

func TestRev(t *testing.T) {
	var x = []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	var expected = []uint16{10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
	var result = rev(x)

	if !compareNumeralString(result, expected) {
		t.Errorf("%s:\nhave %d\nwant %d", t.Name(), result, expected)
	}
}

func TestRevB(t *testing.T) {
	var x = []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	var expected = []byte{0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01}
	var result = RevB(x)

	if !bytes.Equal(result, expected) {
		t.Errorf("%s:\nhave %x\nwant %x", t.Name(), result, expected)
	}
}

func TestGetAsBBytes(t *testing.T) {
	for b := 1; b <= 100; b++ {
		var x = big.NewInt(int64(b))
		// Here we get 1 as 1 byte, 2 as 2 bytes, ...
		var result = getAsBBytes(x, uint64(b))
		if len(result) != b {
			t.Errorf("%s: output is not %d bytes", t.Name(), b)
		}
		var v = big.NewInt(0).SetBytes(result)
		if v.Cmp(x) != 0 {
			t.Errorf("%s:\nhave %s\nwant %s", t.Name(), v, x)
		}
	}
	// Test corner cases
	for b := 1; b <= 100; b++ {
		// x = 256^b - 1 (last value before overflow)
		var x = big.NewInt(256)
		x.Exp(x, big.NewInt(int64(b)), nil)
		x.Sub(x, big.NewInt(1))

		var result = getAsBBytes(x, uint64(b))
		if len(result) != b {
			t.Errorf("%s: output is not %d bytes", t.Name(), b)
		}
		for i := 0; i < len(result); i++ {
			if result[i] != 0xff {
				t.Errorf("%s:\nhave %x", t.Name(), result)
				break
			}
		}
	}
}

func TestNumeralStringToBytes(t *testing.T) {
	var x = []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	var expected = []byte{
		0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
		0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x09}
	var result = NumeralStringToBytes(x)

	if !bytes.Equal(result, expected) {
		t.Errorf("%s:\nhave %x\nwant %x", t.Name(), result, expected)
	}

	// Test corner case (numeral string with maxRadix)
	var inputLength = 100
	x = make([]uint16, inputLength)
	for i := 0; i < len(x); i++ {
		x[i] = maxRadixFF1 - 1
	}
	result = NumeralStringToBytes(x)
	var l = len(result)
	if l != inputLength*2 {
		t.Errorf("%s (Incorrect result length):\nhave %d\nwant %d", t.Name(), l, inputLength*2)
	}
	for i := 0; i < len(result); i++ {
		if result[i] != 0xff {
			t.Errorf("%s (for index %d):\nhave %d\nwant %d", t.Name(), i, result[i], 0xff)
		}
	}
}

func TestBytesToNumeralString(t *testing.T) {
	var x = []byte{
		0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
		0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x09}
	var expected = []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	var result = BytesToNumeralString(x)

	if !compareNumeralString(result, expected) {
		t.Errorf("%s:\nhave %x\nwant %x", t.Name(), result, expected)
	}

	// Test corner case (numeral string with maxRadix)
	var inputLength = 100
	x = make([]byte, inputLength)
	for i := 0; i < len(x); i++ {
		x[i] = 0xff
	}
	result = BytesToNumeralString(x)
	var l = len(result)
	if l != inputLength/2 {
		t.Errorf("%s (Incorrect result length):\nhave %d\nwant %d", t.Name(), l, inputLength/2)
	}
	for i := 0; i < len(result); i++ {
		if result[i] != maxRadixFF1-1 {
			t.Errorf("%s (for index %d):\nhave %d\nwant %d", t.Name(), i, result[i], maxRadixFF1-1)
		}
	}
}

func TestConversions(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < nbrTests; i++ {
		var l = int(rand.Uint32() % 2000) + 10
		var radix = (rand.Uint32() % (maxRadixFF1-10)) + 10
		var x = generateRandomNumeralString(radix, l)
		var result = BytesToNumeralString(NumeralStringToBytes(x))

		if !compareNumeralString(result, x) {
			t.Errorf("%s:\nhave %x\nwant %x", t.Name(), result, x)
		}
	}
}

func generateRandomNumeralString(radix uint32, len int) ([]uint16) {
	var out = make([]uint16, len)
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < len; i++ {
		out[i] = uint16(rand.Uint32() % radix)
	}
	return out
}

func compareNumeralString(a, b []uint16) (bool) {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}