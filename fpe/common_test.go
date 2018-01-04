package fpe

import (
	"github.com/stretchr/testify/assert"
	"math/big"
	"math/rand"
	"testing"
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

	assert.Equal(t, result, expected)
}

func TestNum(t *testing.T) {
	var x = []byte{0x52, 0x1f, 0x6e, 0x4a, 0x88, 0xb7, 0xe0, 0x30}
	var expected = big.NewInt(5917569701788508208)
	var result = num(x)

	assert.Equal(t, result, expected)
}

func TestStrMRadix(t *testing.T) {
	var x = big.NewInt(123456789)
	var expected = []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	var result = strMRadix(10, 10, x)

	assert.Equal(t, result, expected)

	// Test corner cases
	var radix uint32 = maxRadixFF1
	var m uint32 = 10
	x = big.NewInt(int64(radix))
	x.Exp(x, big.NewInt(int64(m)), nil)
	x.Sub(x, big.NewInt(1))
	result = strMRadix(radix, m, x)
	var l = uint32(len(result))

	assert.Equal(t, l, m)
	for _, x := range result {
		assert.Equal(t, x, uint16(maxRadixFF1-1))
	}

	// Test overflow
	radix = uint32(maxRadixFF1)
	m = uint32(10)
	x = big.NewInt(int64(radix))
	x.Exp(x, big.NewInt(int64(m)), nil)

	var f func()
	f = func() {
		strMRadix(radix, m, x)
	}

	assert.Panics(t, f)
}

func TestRev(t *testing.T) {
	var x = []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	var expected = []uint16{10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
	var result = rev(x)

	assert.Equal(t, result, expected)
}

func TestRevB(t *testing.T) {
	var x = []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	var expected = []byte{0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01}
	var result = RevB(x)

	assert.Equal(t, result, expected)
}

func TestGetAsBBytes(t *testing.T) {
	for b := 1; b <= 100; b++ {
		var x = big.NewInt(int64(b))
		// Here we get 1 as 1 byte, 2 as 2 bytes, ...
		var result = getAsBBytes(x, uint64(b))
		assert.Equal(t, len(result), b)

		var v = big.NewInt(0).SetBytes(result)
		assert.Equal(t, v, x)
	}
	// Test corner cases
	for b := 1; b <= 100; b++ {
		// x = 256^b - 1 (last value before overflow)
		var x = big.NewInt(256)
		x.Exp(x, big.NewInt(int64(b)), nil)
		x.Sub(x, big.NewInt(1))

		var result = getAsBBytes(x, uint64(b))
		assert.Equal(t, len(result), b)

		for _, x := range result {
			assert.Equal(t, x, uint8(0xff))
		}
	}
	// Test overflow
	var x = big.NewInt(256)
	var b int64 = 10
	x.Exp(x, big.NewInt(b), nil)

	var f func()
	f = func() {
		getAsBBytes(x, uint64(b))
	}

	assert.Panics(t, f)
}

func TestNumeralStringToBytes(t *testing.T) {
	var x = []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	var expected = []byte{
		0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
		0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x09}
	var result = NumeralStringToBytes(x)

	assert.Equal(t, result, expected)

	// Test corner case (numeral string with maxRadix)
	var inputLength = 100
	x = make([]uint16, inputLength)
	for i := 0; i < len(x); i++ {
		x[i] = maxRadixFF1 - 1
	}
	result = NumeralStringToBytes(x)
	var l = len(result)

	assert.Equal(t, l, inputLength*2)
	for _, x := range result {
		assert.Equal(t, x, uint8(0xff))
	}
}

func TestBytesToNumeralString(t *testing.T) {
	var x = []byte{
		0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
		0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x09}
	var expected = []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	var result = BytesToNumeralString(x)

	assert.Equal(t, result, expected)

	// Test corner case (numeral string with maxRadix)
	var inputLength = 100
	x = make([]byte, inputLength)
	for i := 0; i < len(x); i++ {
		x[i] = 0xff
	}
	result = BytesToNumeralString(x)
	var l = len(result)
	assert.Equal(t, l, inputLength/2)
	for _, x := range result {
		assert.Equal(t, x, uint16(maxRadixFF1-1))
	}
}

func TestConversions(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < nbrTests; i++ {
		var l = int(rand.Uint32()%2000) + 10
		var radix = (rand.Uint32() % (maxRadixFF1 - 10)) + 10
		var x = generateRandomNumeralString(radix, l)
		var result = BytesToNumeralString(NumeralStringToBytes(x))

		assert.Equal(t, result, x)
	}
}

func TestIsNumeralStringValid(t *testing.T) {
	var radix uint32 = 10
	var valid = []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	var invalid = []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	assert.True(t, isNumeralStringValid(valid, radix))
	assert.False(t, isNumeralStringValid(invalid, radix))
}

func TestXorBytes(t *testing.T) {
	var x = []byte{0x0F, 0x0F, 0x0F, 0x0F, 0x0F}
	var y = []byte{0xF0, 0xF0, 0xF0, 0xF0}
	var expected = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00}
	var dst = make([]byte, len(x))

	xorBytes(dst, x, y)
	assert.Equal(t, dst, expected)

}

func generateRandomNumeralString(radix uint32, len int) []uint16 {
	var out = make([]uint16, len)
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < len; i++ {
		out[i] = uint16(rand.Uint32() % radix)
	}
	return out
}

// Mock Block Cipher
type mockBlock struct{}

// Return a block size different from AES (16)
func (c *mockBlock) BlockSize() int          { return 10 }
func (c *mockBlock) Encrypt(dst, src []byte) {}
func (c *mockBlock) Decrypt(dst, src []byte) {}

// Generate random key, tweak an IV for the tests
func getRandomParameters(keySize, tweakSize, ivSize int) (key, tweak, iv []byte) {
	rand.Seed(time.Now().UnixNano())
	key = make([]byte, keySize)
	rand.Read(key)
	tweak = make([]byte, tweakSize)
	rand.Read(tweak)
	iv = make([]byte, ivSize)
	rand.Read(iv)
	return
}
