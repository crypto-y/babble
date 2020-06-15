# Hash Functions
This package implements the hash functions specified in the [noise protocol framework](https://noiseprotocol.org).



# Built-in Hash Functions
Four hash functions are supported, as specified in the [noise specs](https://noiseprotocol.org/noise.html#the-sha256-hash-function).

1. [SHA256](https://en.wikipedia.org/wiki/SHA-2)
2. [SHA512](https://en.wikipedia.org/wiki/SHA-2)
3. [BLAKE2b](https://en.wikipedia.org/wiki/BLAKE_(hash_function))
4. [BLAKE2s](https://en.wikipedia.org/wiki/BLAKE_(hash_function))



# Customize Hash Functions

To create your own hash function, you'll need to implement the interface specified in [`hash.go`](https://github.com/crypto-y/babble/blob/master/hash/hash.go). Once implemented, you need to register it using `Register(Name, Hash)`.

Check [examples/newhash](../examples/newhash/main.go), which implements `SHA3`, once implemented, Once implemented, it can be used via the protocol name,

```go
// register SHA3
noiseHash.Register("SHA3", newSha3)

// Now "SHA3" is a valid hash name, and it can be used in the protocol name as,
p, _ := babble.NewProtocol("Noise_NN_25519_ChaChaPoly_SHA3", "Demo", true)
```

