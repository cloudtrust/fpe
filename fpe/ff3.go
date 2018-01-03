// Package fpe provides an implementation of the FF1 and FF3 mode of operation
// for format-preserving encryption.
// See NIST SP 800-38G (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf).
package fpe

import (
	"crypto/cipher"
	"fmt"
	"math"
	"math/big"
)

const (
	// The number of Feistel rounds must be 8.
	roundsFF3 = 8
	// The tweak must be 8 bytes.
	tweakLenFF3 = 8
	// The radix must be in [2..2^16].
	minRadixFF3 = 2
	maxRadixFF3 = 1 << 16
	// The minimum length of the numeral string is 2.
	minInputLenFF3 = 2
	// The internal cipher's block size (16 bytes for AES).
	blockSizeFF3 = 16
)

type ff3 struct {
	aesBlock cipher.Block
	tweak    []byte
	radix    uint32
}

func newFF3(aesBlock cipher.Block, tweak []byte, radix uint32) *ff3 {
	return &ff3{
		aesBlock: aesBlock,
		tweak:    dup(tweak),
		radix:    radix,
	}
}

type ff3Encrypter ff3

// NewFF3Encrypter returns a BlockMode which encrypts in FF3 mode, using the given
// Block. The given block must be AES, the length of tweak must be 64 bits, and
// the radix must be in [2..2^16].
func NewFF3Encrypter(aesBlock cipher.Block, tweak []byte, radix uint32) cipher.BlockMode {
	if len(tweak) != tweakLenFF3 {
		panic(fmt.Sprintf("NewFF3Encrypter: tweak must be %d bytes.", tweakLenFF3))
	}
	if radix < minRadixFF3 || radix > maxRadixFF3 {
		panic(fmt.Sprintf("NewFF3Encrypter: radix must be in [%d..%d].", minRadixFF3, maxRadixFF3))
	}
	if aesBlock.BlockSize() != blockSizeFF3 {
		panic(fmt.Sprintf("NewFF3Encrypter: block size must be %d bytes.", blockSizeFF3))
	}
	return (*ff3Encrypter)(newFF3(aesBlock, tweak, radix))
}

func (x *ff3Encrypter) CryptBlocks(dst, src []byte) {
	var radix = x.radix
	var tweak = x.tweak

	// Convert the src byte string to a numeral string. We use this to be compliant with the Go BlockMode interface.
	var numeralString = BytesToNumeralString(src)
	var n = len(numeralString)

	if n < minInputLenFF3 || n > maxLength(radix) {
		panic("FF3Encrypter/CryptBlocks: src length not supported.")
	}
	if math.Pow(float64(radix), float64(n)) < 100 {
		panic("FF3Encrypter/CryptBlocks: radix^len < 100.")
	}
	if len(dst) != len(src) {
		panic("FF3Encrypter/CryptBlocks: src and dst size must be equal.")
	}
	if !isNumeralStringValid(numeralString, radix) {
		panic("FF3Encrypter/CryptBlocks: numeral string not valid.")
	}

	var u = uint32(math.Ceil(float64(n) / 2))
	var v = uint32(n) - u
	var a = numeralString[:u]
	var b = numeralString[u:]
	var tl = tweak[:4]
	var tr = tweak[4:]

	for i := uint32(0); i < roundsFF3; i++ {
		var w []byte
		var m uint32
		if i%2 == 0 {
			m = u
			w = tr
		} else {
			m = v
			w = tl
		}
		var p = getFF3P(w, i, radix, b)
		var s = getFF3S(p, x.aesBlock)
		var y = num(s)
		var c = getFF3CEnc(a, y, radix, m)
		copy(a, rev(strMRadix(radix, m, c)))
		a, b = b, a
	}
	copy(dst, NumeralStringToBytes(numeralString))
}

func (x *ff3Encrypter) BlockSize() int {
	return blockSizeFF3
}

func (x *ff3Encrypter) SetTweak(tweak []byte) {
	if len(tweak) != tweakLenFF3 {
		panic(fmt.Sprintf("FF3Encrypter/SetTweak: tweak must be %d bytes.", tweakLenFF3))
	}
	copy(x.tweak, tweak)
}

func (x *ff3Encrypter) SetRadix(radix uint32) {
	if radix < minRadixFF3 || radix > maxRadixFF3 {
		panic(fmt.Sprintf("FF3Encrypter/SetRadix: radix must be in [%d..%d].", minRadixFF3, maxRadixFF3))
	}
	x.radix = radix
}

type ff3Decrypter ff3

// NewFF3Decrypter returns a FpeMode which decrypts in FF3 mode, using the given
// Block. The given block must be AES, the radix must be in [2..2^16], the
// length of tweak must be 64 bits and the tweak must be the same as the tweak
// used to encrypt the data.
func NewFF3Decrypter(aesBlock cipher.Block, tweak []byte, radix uint32) cipher.BlockMode {
	if len(tweak) != tweakLenFF3 {
		panic(fmt.Sprintf("NewFF3Decrypter: tweak must be %d bytes.", tweakLenFF3))
	}
	if radix < minRadixFF3 || radix > maxRadixFF3 {
		panic(fmt.Sprintf("NewFF3Decrypter: radix must be in [%d..%d].", minRadixFF3, maxRadixFF3))
	}
	if aesBlock.BlockSize() != blockSizeFF3 {
		panic(fmt.Sprintf("NewFF3Decrypter: block size must be %d bytes.", blockSizeFF3))
	}
	return (*ff3Decrypter)(newFF3(aesBlock, tweak, radix))
}

func (x *ff3Decrypter) CryptBlocks(dst, src []byte) {
	var radix = x.radix
	var tweak = x.tweak

	// Convert the src byte string to a numeral string. We use this to be compliant with the Go BlockMode interface.
	var numeralString = BytesToNumeralString(src)
	var n = len(numeralString)

	if n < minInputLenFF3 || n > maxLength(radix) {
		panic("FF3Decrypter/CryptBlocks: src length not supported.")
	}
	if math.Pow(float64(radix), float64(n)) < 100 {
		panic("FF3Decrypter/CryptBlocks: radix^len < 100.")
	}
	if len(dst) != len(src) {
		panic("FF3Decrypter/CryptBlocks: src and dst size must be equal.")
	}
	if !isNumeralStringValid(numeralString, radix) {
		panic("FF3Decrypter/CryptBlocks: numeral string not valid.")
	}

	var u = uint32(math.Ceil(float64(n) / 2))
	var v = uint32(n) - u
	var a = numeralString[:u]
	var b = numeralString[u:]
	var tl = tweak[:4]
	var tr = tweak[4:]

	for i := roundsFF3 - 1; i >= 0; i-- {
		var w []byte
		var m uint32
		if i%2 == 0 {
			m = u
			w = tr
		} else {
			m = v
			w = tl
		}
		var p = getFF3P(w, uint32(i), radix, a)
		var s = getFF3S(p, x.aesBlock)
		var y = num(s)
		var c = getFF3CDec(b, y, radix, m)
		copy(b, rev(strMRadix(radix, m, c)))
		a, b = b, a
	}
	copy(dst, NumeralStringToBytes(numeralString))
}

func (x *ff3Decrypter) BlockSize() int {
	return blockSizeFF3
}

func (x *ff3Decrypter) SetTweak(tweak []byte) {
	if len(tweak) != tweakLenFF3 {
		panic(fmt.Sprintf("FF3Decrypter/SetTweak: tweak must be %d bytes.", tweakLenFF3))
	}
	copy(x.tweak, tweak)
}

func (x *ff3Decrypter) SetRadix(radix uint32) {
	if radix < minRadixFF3 || radix > maxRadixFF3 {
		panic(fmt.Sprintf("FF3Decrypter/SetRadix: radix must be in [%d..%d].", minRadixFF3, maxRadixFF3))
	}
	x.radix = radix
}

// maxLength takes an integer radix. It returns the maximum length of the input numeral string
// computed as maxlen = 2 * floor(log_radix(2^96)).
func maxLength(radix uint32) int {
	return 2 * int(math.Floor(math.Log2(math.Pow(2, 96))/math.Log2(float64(radix))))
}

// getFF3P takes a byte string w, the integers i, radix and a numeral string x. It returns
// p = w xor [i]4 || [numRadix(rev(x))]12, where [x]y means x represented as a string of s bytes.
func getFF3P(w []byte, i, radix uint32, x []uint16) []byte {
	var p = make([]byte, blockSizeFF3)

	p[0] = w[0] ^ byte(i>>24)
	p[1] = w[1] ^ byte(i>>16)
	p[2] = w[2] ^ byte(i>>8)
	p[3] = w[3] ^ byte(i)
	copy(p[4:], getAsBBytes(numRadix(rev(x), radix), 12))

	return p
}

// getFF3S takes a byte string p and an AES Block. It returns s = revB(aes.Encrypt(revB(p))).
func getFF3S(p []byte, aesBlock cipher.Block) []byte {
	var s = RevB(p)
	aesBlock.Encrypt(s, s)
	s = RevB(s)
	return s
}

// getFF3CEnc takes a numeral string x, and the integers y, radix and m. It returns
// c = (numRadix(rev(x), radix) + y) mod radix^m.
func getFF3CEnc(x []uint16, y *big.Int, radix, m uint32) *big.Int {
	var c = numRadix(rev(x), radix)
	c.Add(c, y)
	var radixM = big.NewInt(0).Exp(big.NewInt(int64(radix)), big.NewInt(int64(m)), nil)
	c.Mod(c, radixM)
	return c
}

// getFF3CDec takes a numeral string x, and the integers y, radix and m. It returns
// c = (numRadix(rev(x), radix) - y) mod radix^m.
func getFF3CDec(x []uint16, y *big.Int, radix, m uint32) *big.Int {
	var c = numRadix(rev(x), radix)
	c.Sub(c, y)
	var radixM = big.NewInt(0).Exp(big.NewInt(int64(radix)), big.NewInt(int64(m)), nil)
	c.Mod(c, radixM)
	return c
}
