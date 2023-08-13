# RSA
> A pure Vlang implementation of the RSA cryptosystem

## Usage

Install it with v:

```bash
v install LvMalware.rsa
```

Alternatively, you can add it to your `v.mod` like so:

```
Module {
        name: 'mypackage'
        description: 'Description'
        version: '0.0.1'
        license: 'GPLv3.0+'
        dependencies: ['LvMalware.rsa']
}
```

## Example program

```V
import lvmalware.rsa
import lvmalware.rsa.oeap

fn main() {
    // generate a RSA keypair of 1024 bits (this can be a little slow)
    key := rsa.generate_keypair(1024)!
    // RSA OEAP with sha1 by default
    cipher := oeap.OEAP {
        keypair: key
    }

    plaintext  := "My secret message"
    ciphertext := cipher.encrypt(plaintext.bytes(), [])!
    println("Ciphertext: ${ciphertext.hex()}")
    decrypted  := cipher.decrypt(ciphertext, [])!
    assert decrypted.bytestr() == plaintext, "Failed to decrypt"
    println("Plaintext: ${decrypted.bytestr()}")
}
```
