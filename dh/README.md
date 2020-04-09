# DH Functions

This package implements the DH functions, as specified in the noise specs.

### Built-in Curves

The following curves are supported,

**[Curve25519](https://en.wikipedia.org/wiki/Curve25519)**

The protocol name is `25519`, e.g., Noise_XX_**25519**\_AESGCM_SHA256.

**[Curve448](https://en.wikipedia.org/wiki/Curve448)**

The protocol name is `448`, e.g., Noise_XX_**448**\_AESGCM_SHA256.

**[Secp256k1](https://en.bitcoin.it/wiki/Secp256k1)**

The protocol name is `secp256k1`, e.g., Noise_XX_**secp256k1**\_AESGCM_SHA256.



### Customized DH function

To create your own DH function, you'll need to implement the interfaces specified in [`dh.go`](https://github.com/yyforyongyu/noise/blob/master/dh/dh.go), which requires a  `PublicKey` interface, a `PrivateKey` interface and a `Curve` interface. And you need to register it using `Register(Name, Curve)`.

