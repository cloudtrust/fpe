# fpe
This is an implementation of the NIST Special Publication 800-38G, Recommendation for Block Cipher Modes of Operation: Methods for Format-Preserving Encryption.

Implementations of the FF1 and FF3 schemes are provided.

FF1 example:
```golang
// FF1 Example
var key = make([]byte, 16)
rand.Read(key)
var tweak = make([]byte, 20)
rand.Read(tweak)
var radix = uint32(10)
var plaintext = []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

// Create AES Block used by FF1.
var aesBlock, err = aes.NewCipher(key)
if err != nil {
	fmt.Printf("NewCipher = %s", err)
}

// Create CBC mode used by FF1.
var iv = make([]byte, 16)
var cbcMode = cipher.NewCBCEncrypter(aesBlock, iv)

// Create FF1 Encrypter and encrypt numeral string
var encrypter = fpe.NewFF1Encrypter(aesBlock, cbcMode, tweak, radix)
// We use NumeralStringToBytes and BytesToNumeralString to be compliant with the Go BlockMode interface.
var x = fpe.NumeralStringToBytes(plaintext)
encrypter.CryptBlocks(x, x)
var ciphertext = fpe.BytesToNumeralString(x)

// Create FF1 Decrypter and decrypt numeral string
var decrypter = fpe.NewFF1Decrypter(aesBlock, cbcMode, tweak, radix)
// We use NumeralStringToBytes and BytesToNumeralString to be compliant with the Go BlockMode interface.
var y = fpe.NumeralStringToBytes(ciphertext)
decrypter.CryptBlocks(y, y)
var decrypted = fpe.BytesToNumeralString(y)

// Print values
fmt.Printf("FF1 example:\n")
fmt.Printf("Plaintext:  %d\n", plaintext)
fmt.Printf("Ciphertext: %d\n", ciphertext)
fmt.Printf("Decrypted:  %d\n", decrypted)
```

FF3 example:
Note that there is a specificity with the FF3 algorithm. The standard specifies that we must revert the bytes of the symmetric key (see: aes.NewCipher(fpe.RevB(key)). 
If this is not done, it will affect interoperability.
```golang
// FF3 Example
var key = make([]byte, 16)
rand.Read(key)
var tweak = make([]byte, 8)
rand.Read(tweak)
var radix = uint32(10)
var plaintext = []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

// Create AES Block used by FF3.
var aesBlock, err = aes.NewCipher(fpe.RevB(key))
if err != nil {
	fmt.Printf("NewCipher = %s", err)
}

// Create FF3 Encrypter and encrypt numeral string
var encrypter = fpe.NewFF3Encrypter(aesBlock, tweak, radix)
// We use NumeralStringToBytes and BytesToNumeralString to be compliant with the Go BlockMode interface.
var x = fpe.NumeralStringToBytes(plaintext)
encrypter.CryptBlocks(x, x)
var ciphertext = fpe.BytesToNumeralString(x)

// Create FF3 Decrypter and decrypt numeral string
var decrypter = fpe.NewFF3Decrypter(aesBlock, tweak, radix)
// We use NumeralStringToBytes and BytesToNumeralString to be compliant with the Go BlockMode interface.
var y = fpe.NumeralStringToBytes(ciphertext)
decrypter.CryptBlocks(y, y)
var decrypted = fpe.BytesToNumeralString(y)

// Print values
fmt.Printf("FF3 example:\n")
fmt.Printf("Plaintext:  %d\n", plaintext)
fmt.Printf("Ciphertext: %d\n", ciphertext)
fmt.Printf("Decrypted:  %d\n", decrypted)
```

To encipher data such as Strings or Credit Cards, see the [helpers](https://github.com/cloudtrust/fpe-field-format).

# There are attacks on the NIST standard

The first is described in the publication [Message-recovery attacks on Feistel-based Format Preserving Encryption](https://eprint.iacr.org/2016/794.pdf) by Bellare, Hoang, and Tessaro. On page 5 of the same document, the authors suggest a simple fix: increasing the number of Feistel rounds.

The second attack targets FF3 and is described in the publication [Breaking The FF3 Format-Preserving Encryption Standard Over Small Domains](https://eprint.iacr.org/2017/521.pdf) by F. Durak and S. Vaudenay. The publication also describes how to fix FF3. The NIST published a [statement](https://beta.csrc.nist.gov/News/2017/Recent-Cryptanalysis-of-FF3) and expects to revise the standard, either to fix or withdraw FF3.

We provide the branch [fpe-fix](https://github.com/cloudtrust/fpe/tree/fpe-fix) that includes both fixes. That is an augmented number of rounds and the modification of FF3. However, this branch does not comply with the standard anymore, and there are no test vectors to validate it.

