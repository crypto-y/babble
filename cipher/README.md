# Cipher Functions
This package implements the cipher functions specified in the [noise protocol framework](https://noiseprotocol.org).



# Built-in Ciphers
Two cipher functions are supported, as specified in the [noise specs](https://noiseprotocol.org/noise.html#cipher-functions).

1. [AESGCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)

   AESGCM is implemented based upon the official Go cipher package `crypto/aes`. Use it with caution though, as the AES operations in the `crypto/aes` package are not implemented using constant-time algorithms, which makes it vunerable to [side channel attack](https://en.wikipedia.org/wiki/Side-channel_attack).

   However, if the package is running on systems with [hardware support for AES](https://en.wikipedia.org/wiki/AES_instruction_set) then it won't be an issue. More details can be found following this [discussion](https://github.com/golang/go/issues/16821).

   As for this package, AESGCM is tuned based on the [noise specs](https://noiseprotocol.org/noise.html#the-aesgcm-cipher-functions):

   > AES256 with GCM with a 128-bit tag appended to the ciphertext. The 96-bit nonce is formed by encoding 32 bits of zeros followed by big-endian encoding of n.

2. [ChaChaPoly](https://tools.ietf.org/html/rfc7539)

   ChaChaPoly is implemented based on `golang.org/x/crypto/chacha20poly1305` by using the ChaCha20-Poly1305 AEAD.



# Customized Cipher Functions

To create your own cipher function, you'll need to implement the interface specified in [`cipher.go`](https://github.com/crypto-y/babble/blob/master/cipher/cipher.go). Once implemented, you need to register it using `Register(Name, Cipher)`.

Check [examples/newcipher](../examples/newcipher/main.go), which implements `ChaChaPolyX`, once implemented, Once implemented, it can be used via the protocol name,

```go
// Register it for package babble.
noiseCipher.Register("ChaChaPolyX", newCipher)

// Now "ChaChaPolyX" is a valid hash name, and it can be used in the protocol name as,
p, _ := babble.NewProtocol("Noise_NN_25519_ChaChaPolyX_BLAKE2s", "Demo", true)
```



When registering new cipher functions, it won't check the size of AD (as in `cipher.Cipher().Overhead()`). While a 16-byte AD size is specified by the noise protocol framework, it's up to the application to decide the actual size to be used when registering new functions.