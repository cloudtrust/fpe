// FF1 (Format-preserving, Feistel-based encryption) mode.
//
// Format-preserving encryption (FPE) is designed for data that is not
// necessarily binary. In particular, given any finite set of symbols,
// like the decimal numerals, a method for FPE transforms data that is
// formatted as a sequence of the symbols in such a way that the encrypted
// form of the data has the same format, including the length, as the
// original data.
//
// See NIST SP 800-38G, pp 16-19.
package fpe

import (
	"math"
	"math/big"
	"fmt"
)

const (
	// The tweak length must be in [0..maxTweakLenFF1].
	minTweakLenFF1 = 0
	maxTweakLenFF1 = 1 << 16
	// The radix must be in [2..2^16].
	minRadixFF1 = 2
	maxRadixFF1 = 1 << 16
	// The numeral string length must be in [2..2^32[.
	minInputLenFF1 = 2
	maxInputLenFF1 = (1 << 32) - 1
	// The internal cipher's block size (16 bytes for AES).
	blockSizeFF1 = 16
)

type cbcWithSetIV interface {
	BlockMode
	SetIV([]byte)
}

type ff1 struct {
	aesBlock  Block
	cbcMode   cbcWithSetIV
	tweak     []byte
	radix     uint32
}

func newFF1(aesBlock Block, cbcMode cbcWithSetIV, tweak []byte, radix uint32) *ff1 {
	return &ff1{
		aesBlock:  aesBlock,
		cbcMode:   cbcMode,
		tweak:     dup(tweak),
		radix:     radix,
	}
}

type ff1Encrypter ff1

// NewFF1Encrypter returns a BlockMode which encrypts in FF1 mode, using the given
// Block and BlockMode. The given block must be AES, the BlockMode must be CBC, the
// length of tweak must be in [0..maxTweakLenFF1], and the radix must be in [2..2^16].
func NewFF1Encrypter(aesBlock Block, cbcMode BlockMode, tweak []byte, radix uint32) BlockMode {
	if len(tweak) < minTweakLenFF1 || len(tweak) > maxTweakLenFF1 {
		panic(fmt.Sprintf("NewFF1Encrypter: tweak must be [%d..%d] bytes.", minTweakLenFF1, maxTweakLenFF1))
	}
	if radix < minRadixFF1 || radix > maxRadixFF1 {
		panic(fmt.Sprintf("NewFF1Encrypter: radix must be in [%d..%d].", minRadixFF1, maxRadixFF1))
	}
	if aesBlock.BlockSize() != blockSizeFF1 {
		panic(fmt.Sprintf("NewFF1Encrypter: block size must be %d bytes.", blockSizeFF1))
	}
	var cbcModeWithSetIV, ok = cbcMode.(cbcWithSetIV)
	if !ok {
		panic("NewFF1Encrypter: CBC mode must have a SetIV function.")
	}
	return (*ff1Encrypter)(newFF1(aesBlock, cbcModeWithSetIV, tweak, radix))
}

func (x *ff1Encrypter) CryptBlocks(dst, src []byte) {
	var radix = x.radix
	var tweak = x.tweak
	var t = uint32(len(tweak))

	// Convert the src byte string to a numeral string. We use this to be compliant with the Go BlockMode interface.
	var numeralString = BytesToNumeralString(src)
	var n = uint32(len(numeralString))

	if n < minInputLenFF1 || n > maxInputLenFF1 {
		panic(fmt.Sprintf("FF1Encrypter/CryptBlocks: src length must be in [%d..%d].", minInputLenFF1, maxInputLenFF1))
	}
	if math.Pow(float64(radix), float64(n)) < 100 {
		panic("FF1Encrypter/CryptBlocks: radix^len < 100.")
	}
	if len(dst) != len(src) {
		panic("FF1Encrypter/CryptBlocks: src and dst size must be equal.")
	}
	if !isNumeralStringValid(numeralString, radix) {
		panic("FF1Encrypter/CryptBlocks: numeral string not valid.")
	}

	var u = uint32(math.Floor(float64(n) / 2))
	var v = uint32(n) - u
	var a = numeralString[:u]
	var b = numeralString[u:]
	var beta = getFF1B(v, radix)
	var d = getFF1D(beta)
	var p = getFF1P(radix, u, n, t)

	var roundsFF1 = getFF1NbrRounds(len(numeralString))
	for i := 0; i < roundsFF1; i++ {
		var q = getFF1Q(tweak, radix, beta, i, b)
		var r = prf(x.cbcMode, append(p, q...))
		var s = getFF1S(x.aesBlock, r, d)
		var y = num(s)

		var m uint32
		if i % 2 == 0 {
			m = u
		} else {
			m = v
		}

		var c = getFF1CEnc(a, y, radix, m)
		copy(a, strMRadix(radix, m, c ))
		a, b = b, a
	}
	// Convert the numeral string to a byte string. We use this to be compliant with the Go BlockMode interface.
	copy(dst, NumeralStringToBytes(numeralString))
}

func (x *ff1Encrypter) BlockSize() int {
	return blockSizeFF1
}

func (x *ff1Encrypter) SetTweak(tweak []byte) {
	if len(tweak) < minTweakLenFF1 || len(tweak) > maxTweakLenFF1 {
		panic(fmt.Sprintf("FF1Encrypter/SetTweak: tweak must be [%d..%d] bytes.", minTweakLenFF1, maxTweakLenFF1))
	}
	copy(x.tweak, tweak)
}

func (x *ff1Encrypter) SetRadix(radix uint32) {
	if radix < minRadixFF1 || radix > maxRadixFF1 {
		panic(fmt.Sprintf("FF1Encrypter/SetRadix: radix must be in [%d..%d].", minRadixFF1, maxRadixFF1))
	}
	x.radix = radix
}

type ff1Decrypter ff1

// NewFF1Decrypter returns a BlockMode which decrypts in FF1 mode, using the given
// Block and BlockMode. The given block must be AES, the BlockMode must be CBC, the
// tweak must match the tweak used to encrypt the data, and the radix must be in [2..2^16].
func NewFF1Decrypter(aesBlock Block, cbcMode BlockMode, tweak []byte, radix uint32) BlockMode {
	if len(tweak) < minTweakLenFF1 || len(tweak) > maxTweakLenFF1 {
		panic(fmt.Sprintf("NewFF1Decrypter: tweak must be [%d..%d] bytes.", minTweakLenFF1, maxTweakLenFF1))
	}
	if radix < minRadixFF1 || radix > maxRadixFF1 {
		panic(fmt.Sprintf("NewFF1Decrypter: radix must be in [%d..%d].", minRadixFF1, maxRadixFF1))
	}
	if aesBlock.BlockSize() != blockSizeFF1 {
		panic(fmt.Sprintf("NewFF1Decrypter: block size must be %d bytes.", blockSizeFF1))
	}
	var cbcModeWithSetIV, ok = cbcMode.(cbcWithSetIV)
	if !ok {
		panic("NewFF1Decrypter: CBC mode must have a SetIV function.")
	}
	return (*ff1Decrypter)(newFF1(aesBlock, cbcModeWithSetIV, tweak, radix))
}

func (x *ff1Decrypter) CryptBlocks(dst, src []byte) {
	var radix = x.radix
	var tweak = x.tweak
	var t = uint32(len(tweak))

	// Convert the src byte string to a numeral string. We use this to be compliant with the Go BlockMode interface.
	var numeralString = BytesToNumeralString(src)
	var n = uint32(len(numeralString))

	if n < minInputLenFF1 || n > maxInputLenFF1 {
		panic(fmt.Sprintf("FF1Decrypter/CryptBlocks: src length must be in [%d..%d].", minInputLenFF1, maxInputLenFF1))
	}
	if math.Pow(float64(radix), float64(n)) < 100 {
		panic("FF1Decrypter/CryptBlocks: radix^len < 100.")
	}
	if len(dst) != len(src) {
		panic("FF1Decrypter/CryptBlocks: src and dst size must be equal.")
	}
	if !isNumeralStringValid(numeralString, radix) {
		panic("FF1Decrypter/CryptBlocks: numeral string not valid.")
	}

	var u = uint32(math.Floor(float64(n) / 2))
	var v = uint32(n) - u
	var a = numeralString[:u]
	var b = numeralString[u:]
	var beta = getFF1B(v, radix)
	var d = getFF1D(beta)
	var p = getFF1P(radix, u, n, t)

	var roundsFF1 = getFF1NbrRounds(len(numeralString))
	for i := roundsFF1-1; i >= 0; i-- {
		var q = getFF1Q(tweak, radix, beta, i, a)
		var r = prf(x.cbcMode, append(p, q...))
		var s = getFF1S(x.aesBlock, r, d)
		var y = num(s)

		var m uint32
		if i % 2 == 0 {
			m = u
		} else {
			m = v
		}

		var c = getFF1CDec(b, y, radix, m)
		copy(b, strMRadix(radix, m, c ))
		a, b = b, a
	}
	// Convert the numeral string to a byte string. We use this to be compliant with the Go BlockMode interface.
	copy(dst, NumeralStringToBytes(numeralString))
}

func (x *ff1Decrypter) BlockSize() (int) {
	return blockSizeFF1
}

func (x *ff1Decrypter) SetTweak(tweak []byte){
	if len(tweak) < minTweakLenFF1 || len(tweak) > maxTweakLenFF1 {
		panic(fmt.Sprintf("FF1Decrypter/SetTweak: tweak must be [%d..%d] bytes.", minTweakLenFF1, maxTweakLenFF1))
	}
	copy(x.tweak, tweak)
}

func (x *ff1Decrypter) SetRadix(radix uint32) {
	if radix < minRadixFF1 || radix > maxRadixFF1 {
		panic(fmt.Sprintf("FF1Decrypter/SetRadix: radix must be in [%d..%d].", minRadixFF1, maxRadixFF1))
	}
	x.radix = radix
}

// getFF1B takes an integer v and an integer radix. It returns b = ceil(ceil(v * log2(radix)) / 8).
func getFF1B(v, radix uint32) (uint64){
	return uint64(math.Ceil(math.Ceil(float64(v) * math.Log2(float64(radix))) / 8))
}

// getFF1D takes an integer beta. It returns d = 4 * ceil(beta / 4) + 4.
func getFF1D(beta uint64) (uint64){
	return uint64(4 * math.Ceil(float64(beta) / 4) + 4)
}

// getFF1P takes the integers radix, u, n, and t. It returns the byte string
// p = [1]1 || [2]1 || [1]1 || [radix]3 || [10]1 || [u mod 256]1 || [n]4 || [t]4,
// where [x]y means x represented as a string of s bytes.
func getFF1P(radix, u, n, t uint32) ([]byte){
	var p = make([]byte, blockSizeFF1)

	p[0], p[1], p[2] = 1, 2, 1
	p[3], p[4], p[5] = byte(radix >> 16), byte(radix >> 8), byte(radix)
	p[6] = 10
	p[7] = byte(u % 256)
	p[8], p[9], p[10], p[11] = byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)
	p[12], p[13], p[14], p[15] = byte(t >> 24), byte(t >> 16), byte(t >> 8), byte(t)

	return p
}

// getFF1Q takes a byte string tweak, the integers radix, beta, i, and the numeral string x.
// It returns the byte string q = tweak || [0](-t-b-1) mod 16 || [i]1 || [numRadix(x, radix)]b,
// where [x]y means x represented as a string of s bytes.
func getFF1Q(tweak []byte, radix uint32, b uint64, i int, x []uint16) ([]byte) {
	var t = uint64(len(tweak))
	var mod = (-1 * int64(t+b+1)) % blockSizeFF1
	// Assure that z is always positive
	var z = uint64((mod + blockSizeFF1) % blockSizeFF1)

	var lenQ = t + z + 1 + b
	var q = make([]byte, lenQ)
	copy(q, tweak)
	q[t+z] = byte(i)
	copy(q[t+z+1:], getAsBBytes(numRadix(x, radix), b))
	return q
}

// prf takes a CBC mode and a byte string x. It encipher x with CBC and returns the final block of the ciphertext.
func prf(cbcMode cbcWithSetIV, x []byte) ([]byte) {
	var l = len(x)
	var ciphertext = make([]byte, l)
	cbcMode.SetIV(make([]byte, blockSizeFF1))

	cbcMode.CryptBlocks(ciphertext, x)

	// return last block
	return ciphertext[l-blockSizeFF1:]
}

// getFF1S takes an AES Block, a byte string r and an integer d. It returns the first d bytes of
// the following string of ceil(d / 16) blocks:
// r || aes.Encrypt(r xor [1]16) || aes.Encrypt(r xor [2]16) || ... || aes.Encrypt(r xor [ceil(d / 16) - 1]16),
// where [x]y means x represented as a string of s bytes.
func getFF1S(aesBlock Block, r []byte, d uint64) ([]byte) {
	var nbrBlocks = uint64(math.Ceil(float64(d) / blockSizeFF1))
	var s = make([]byte, blockSizeFF1 * nbrBlocks)

	copy(s, r)
	for i := uint64(1); i < nbrBlocks; i++ {
		var enc = make([]byte, blockSizeFF1)
		enc[0], enc[1], enc[2], enc[3] = byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)
		xorBytes(enc, enc, r)
		aesBlock.Encrypt(enc, enc)
		copy(s[blockSizeFF1*i:], enc)
	}

	return s[:d]
}

// getFF1CEnc takes a numeral string x, and the integers y, radix and m. It returns
// c = (numRadix(x, radix) + y) mod radix^m.
func getFF1CEnc(x []uint16, y *big.Int, radix uint32, m uint32) (*big.Int) {
	var c = numRadix(x, radix)
	var radixM = big.NewInt(0).Exp(big.NewInt(int64(radix)), big.NewInt(int64(m)), nil)
	c.Add(c, y)
	c.Mod(c, radixM)
	return c
}

// getFF1CDec takes a numeral string x, and the integers y, radix and m. It returns
// c = (numRadix(x, radix) - y) mod radix^m.
func getFF1CDec(x []uint16, y *big.Int, radix uint32, m uint32) (*big.Int) {
	var c = numRadix(x, radix)
	var radixM = big.NewInt(0).Exp(big.NewInt(int64(radix)), big.NewInt(int64(m)), nil)
	c.Sub(c, y)
	c.Mod(c, radixM)
	return c
}

// Fix the attack described in https://eprint.iacr.org/2016/794.pdf by increasing the
// number of rounds.
func getFF1NbrRounds(l int) (int) {
	switch {
	case l >= 32:
		return 12
	case l >= 20:
		return 18
	case l >= 14:
		return 24
	case l >= 10:
		return 30
	default:
		return 36
	}
}
