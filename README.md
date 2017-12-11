# Format-preserving encryption (FPE) [![Build Status](https://travis-ci.org/cloudtrust/fpe.svg?branch=master)](https://travis-ci.org/cloudtrust/fpe)

Cloudtrust FPE provides an implementation of the FF1 and FF3 mode of operation for  format-preserving encryption from the [NIST Special Publication 800-38G](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf).
There are attacks on the NIST standard. The branch [fpe-fix](https://github.com/cloudtrust/fpe/tree/fpe-fix) includes the fixes described in [this](#attacks-on-the-nist-standard) section.
The FPE schemes cannot be used as is. We need to define formats, validate and convert data to  inputs that can be treated by FF1 and FF3, and finally convert the outputs back to the desired format. This task is delicate, and if not done correctly can have catastrophic consequences such as security issues or data loss (unability to decipher encrypted data).
Some of the most common formats like credit cards, string, or numbers are provided in the [helper](https://github.com/cloudtrust/fpe-field-format) repository.

## What is FPE?
Format preserving encryption is a special area of symmetric cryptography, that allows some control over the ciphertext format. Here we consider the FF1 and FF3 schemes. There are other algorithms, but at the time of writing none of them are standardised.

To illustrate FPE, let us imagine we want to encipher a credit card number (CCN). The first thought is to use the Advanced Encryption Standard (AES) with a mode of operation such as CBC, GCM, ...
For example, the encryption of the CCN "5567 8033 4858 3023" will yield a ciphertext of the form "0HTC5WQQKU5EU8zGDPPKqQ==". Here we had to Base64 encode it, because it contains non-printable characters. 
With FPE algorithms, we can control the format of the ciphertext. This time, the encryption of the preceding CCN will look like "1453 7959 2420 4601".

## When should you use FPE?
In a perfect world: never. Security should be a primary concern since the beginning of the design process of every system, so it can be tightly integrated into it. The encryption algorithm should be secure, efficient, flexible... This is the goal of Rijndael, which won the 2000 AES competition and was renamed AES in the NIST FIPS 197 standard. The AES was thorougly analysed by some of the bests cryptographs in the world and resists attacks since 2000. It is now widely used, so a lot of processors provides hardware instructions to speed up encryption with AES, which make it very efficient. This is the kind of algorithm we want to use.
The FPE standard is new, and there is already attacks (see section below). Moreover, it is less efficient, less flexible and more delicate to use than AES. 

However, sometimes it is just not possible to use AES. For example if we have to secure legacy systems whithout performing considerable and costly modifications, to encipher database fields without modifying the schema, or any other use case where the data is expected to be of a specific format. This is for such cases that FPE was engineered.

Cloudtrust FPE
This repository provides an implementation of the FF1 and FF3 schemes from the NIST SP800-38G.

## FF1
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

## FF3
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


## Attacks on the NIST Standard 
The first is described in the publication [Message-recovery attacks on Feistel-based Format Preserving Encryption](https://eprint.iacr.org/2016/794.pdf) by Bellare, Hoang, and Tessaro. On page 5 of the same document, the authors suggest a simple fix: increasing the number of Feistel rounds.

The second attack targets FF3 and is described in the publication [Breaking The FF3 Format-Preserving Encryption Standard Over Small Domains](https://eprint.iacr.org/2017/521.pdf) by F. Durak and S. Vaudenay. The publication also describes how to fix FF3. The NIST published a [statement](https://beta.csrc.nist.gov/News/2017/Recent-Cryptanalysis-of-FF3) and expects to revise the standard, either to fix or withdraw FF3.

We provide the branch [fpe-fix](https://github.com/cloudtrust/fpe/tree/fpe-fix) that includes both fixes. That is an augmented number of rounds and the modification of FF3. However, this branch does not comply with the standard anymore, and there are no test vectors to validate it.

