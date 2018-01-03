# Format-preserving encryption (FPE) [![Build Status](https://travis-ci.org/cloudtrust/fpe.svg?branch=fpe-fix)](https://travis-ci.org/cloudtrust/fpe) [![Coverage Status](https://coveralls.io/repos/github/cloudtrust/fpe/badge.svg?branch=fpe-fix)](https://coveralls.io/github/cloudtrust/fpe?branch=fpe-fix) [![Go Report Card](https://goreportcard.com/badge/github.com/cloudtrust/fpe)](https://goreportcard.com/report/github.com/cloudtrust/fpe)

Cloudtrust FPE provides an implementation of the FF1 and FF3 mode of operation for format-preserving encryption from the [NIST Special Publication 800-38G](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf).

There are attacks on the NIST standard. The branch [fpe-fix](https://github.com/cloudtrust/fpe/tree/fpe-fix) includes the fixes described in [this](#attacks-on-the-nist-standard) section.

The FPE schemes cannot be used as is. We need to define formats, validate and convert data to inputs that can be treated by FF1 and FF3, and finally convert the outputs back to the desired format. This task is delicate, and if not done correctly can have severe consequences such as security issues or data loss (unability to decipher encrypted data).
Some of the most common formats like credit cards, string, or numbers are provided in the [helper](https://github.com/cloudtrust/fpe-field-format) repository.

### What is FPE?
In the following sections, we consider the FF1 and FF3 schemes. There are other algorithms, but at the time of writing none of them are standardised.

Format preserving encryption is a special area of symmetric cryptography, that allows some control over the ciphertext format.
Let us imagine we want to encipher a credit card number (CCN). The first thought is to use the Advanced Encryption Standard (AES) with a mode of operation such as CBC, GCM, ...

For example, the encryption of the CCN "5567 8033 4858 3023" will yield a ciphertext of the form "0HTC5WQQKU5EU8zGDPPKqQ==". Here we had to Base64 encode it, because it contains non-printable characters. 
With FPE algorithms, we can control the format of the ciphertext. This time, the encryption of the preceding CCN will look like "1453 7959 2420 4601".

### When should you use FPE?
Ideally, never.
The FPE standard is new, and there is already attacks (see section below). Moreover, it is less efficient, less flexible and more delicate to use than AES. So if you have the choice, use AES.

Unfortunately, sometimes it is just not possible to use AES. For example if we have to secure legacy systems whithout performing considerable and costly modifications, to encipher database fields without modifying the schema, or any other use case where the data is expected to be of a specific format. This is for such cases that FPE was designed.
§
## How to use Cloudtrust FPE
FF1 and FF3 can encipher numeral strings (see the NIST standard for more details). The plaintext and ciphertext are of the type []uint16.
We chose to be compatible with the cipher.Blockmode interface, and propose two functions to convert the numeral string to inputs compatible with it, i.e. []byte.

To encipher/decipher with FF1/FF3, we need to:
1. Get a FF1/FF3 encrypter/decrypter
1. Convert the numeral string to a byte string (to satisfy the Blockmode interface)
1. Encrypt/decrypt
1. Convert the byte string to numeral string

```golang
var encrypter, err = getFF3Encrypter(key, tweak, radix)
if err != nil {
    // Deal with error
}
var plaintextBytes = fpe.NumeralStringToBytes(plaintextNumeralString)
encrypter.CryptBlocks(ciphertextBytes, plaintextBytes)
var ciphertextNumeralString = fpe.BytesToNumeralString(ciphertextBytes)
```

### FF1

The function below shows how to create a FF1 encrypter. For a decrypter, juste replace NewFF1Encrypter with NewFF1Decrypter.
```golang
func getFF1Encrypter(key, tweak []byte, radix uint32) (cipher.BlockMode, error) {
    // Create AES Block used by FF1.
    var aesBlock, err = aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    // Create CBC mode used by FF1.
    var iv = make([]byte, blockSizeFF1)
    var cbcMode = cipher.NewCBCEncrypter(aesBlock, iv)

    // Create FF1 Encrypter.
    var encrypter = NewFF1Encrypter(aesBlock, cbcMode, tweak, radix)

    return encrypter, nil
}
```

### FF3

The function below shows how to create a FF3 encrypter. For a decrypter, juste replace NewFF3Encrypter with NewFF3Decrypter.

```golang
func getFF3Encrypter(key, tweak []byte, radix uint32) (cipher.BlockMode, error) {
    // Create AES Block used by FF3.
    var aesBlock, err = aes.NewCipher(fpe.RevB(key))
    if err != nil {
        return nil, err
    }

    // Create FF3 Encrypter.
    var encrypter = NewFF3Encrypter(aesBlock, tweak, radix)

    return encrypter, nil
}
```

Note that there is a specificity with the FF3 algorithm. The standard specifies that we must revert the bytes of the symmetric key (see: `aes.NewCipher(fpe.RevB(key)`). 
If this is not done, it will affect interoperability.

## Attacks on the NIST Standard
There are attacks on the NIST Standard. The first is described in the publication [Message-recovery attacks on Feistel-based Format Preserving Encryption](https://eprint.iacr.org/2016/794.pdf) by Bellare, Hoang, and Tessaro. On page 5 of the same document, the authors suggest a simple fix: increasing the number of Feistel rounds.

The second attack targets FF3 and is described in the publication [Breaking The FF3 Format-Preserving Encryption Standard Over Small Domains](https://eprint.iacr.org/2017/521.pdf) by Durak and Vaudenay. The publication also describes how to fix FF3. The NIST published a [statement](https://beta.csrc.nist.gov/News/2017/Recent-Cryptanalysis-of-FF3) and expects to revise the standard, either to fix or withdraw FF3.

We provide the branch [fpe-fix](https://github.com/cloudtrust/fpe/tree/fpe-fix) that includes both fixes. That is an augmented number of rounds and the modification of FF3. However, this branch does not comply with the standard anymore, and there are no test vectors to validate it.