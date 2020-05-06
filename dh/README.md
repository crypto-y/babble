# DH Functions

This package implements the DH functions, as specified in [the noise specs](https://noiseprotocol.org/noise.html#dh-functions).

### Built-in Curves

The following curves are supported,

**[Curve25519](https://en.wikipedia.org/wiki/Curve25519)**

The protocol name is `25519`, e.g., Noise_XX_**25519**\_AESGCM_SHA256.

**[Curve448](https://en.wikipedia.org/wiki/Curve448)**

The protocol name is `448`, e.g., Noise_XX_**448**\_AESGCM_SHA256.

**[Secp256k1](https://en.bitcoin.it/wiki/Secp256k1)**

The protocol name is `secp256k1`, e.g., Noise_XX_**secp256k1**\_AESGCM_SHA256.



### Customized DH function

To create your own DH function, you'll need to implement the interfaces specified in [`dh.go`](dh.go), which requires a  `PublicKey` interface, a `PrivateKey` interface and a `Curve` interface. And you need to register it using `Register(Name, Curve)`.

Check [examples/newdh](../examples/newdh/main.go), which implements a dummy DH function for demonstration. Once implemented, it can be used via the protocol name,

```go
// dumb implements the DH interface for DumbCurve.
dh.Register("Dumb", newDumbCurve)

// Now "Dumb" is a valid dh curve name, and it can be used in the protocol name as,
p, _ := babble.NewProtocol("Noise_NN_Dumb_ChaChaPoly_BLAKE2s", "Demo", true)
```

