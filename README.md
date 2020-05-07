# Babble

[![Build Status](https://travis-ci.org/yyforyongyu/babble.svg?branch=master)](https://travis-ci.org/yyforyongyu/babble.svg?branch=master) [![codecov](https://codecov.io/gh/yyforyongyu/babble/branch/master/graph/badge.svg)](https://codecov.io/gh/yyforyongyu/babble) [![Go Report Card](https://goreportcard.com/badge/github.com/yyforyongyu/babble)](https://goreportcard.com/report/github.com/yyforyongyu/babble) [![GoDoc](https://godoc.org/github.com/yyforyongyu/babble?status.svg)](https://godoc.org/github.com/yyforyongyu/babble)

Babble is the Go implementation of the [Noise Protocol Framework](https://noiseprotocol.org/).

Being a framework, the essence is to have the ability to construct new protocols by applying any cryptographically secure functions. With extensibility in mind, babble makes it easy to add any new patterns, cipher functions, hash functions, and DH functions.

The current built-in components are summerized as follows,

- DH curves: `curve448`, `curve25519` and `secp256k1`.
- Ciphers: `ChaCha20-Poly1305` and `AESGCM`.
- Hash functions: `SHA256`, `SHA512`, `BLAKE2b` and `BLAKE2s`.
- Patterns: all the patterns [defined here](https://noiseprotocol.org/noise.html#handshake-patterns), with PSK mode supported.



Note: the current version doesn't implement the `fallback` mode.



# Usage

To use, import the package `babble`,

```go
import "github.com/yyforyongyu/babble"
```

In addition to the main package `babble`, there are five packages which can be used for customization, see [Extentable Components](#Extentable-Components).

```go
"github.com/yyforyongyu/babble/cipher"
"github.com/yyforyongyu/babble/dh"
"github.com/yyforyongyu/babble/hash"
"github.com/yyforyongyu/babble/rekey"
"github.com/yyforyongyu/babble/pattern"
```

**WARNING**: The Go's implementation of  `AESGCM` might be vunerable to side channel attack, please read [the documentation](cipher) if you plan to use it.

There are two methods can be used for contructing new handshake state, `NewProtocol` and `NewProtocolWithConfig`.



### NewProtocol

```go
func NewProtocol(name, prologue string, initiator bool) (*HandshakeState, error)
```

The `NewProtocol` is used for quickly creating a new `HandshakeState` using the `name` and `prologue`, along with an `initiator` specifying whether the caller is an initiator or a responder.

```go
// creates a new handshake state using pattern NN, curve 25519, cipher
// ChaChaPoly and hash function BLAKE2s.
p, _ := babble.NewProtocol("Noise_NN_25519_ChaChaPoly_BLAKE2s", "Demo", true)
```

This function uses a default `rekeyer`, which rotates the cipher key every 10000 encryption/decription and resets the nonce to be zero, read [this documentation](rekey) for detailed specs.

While it's convenient to create a protocol with three parameters, it's not achieved without a cost, in which only a limited number of patterns are supported when using `NewProtocol`. In particular,

- The pre-message pattern is not supported, as it requires either one or both static public keys to be known before the handshake.
- Pre-shared symmetric key, `PSK`, is not supported, as it required both parties to specify a PSK before the handshake.

```go
// returns an error if the NewProtocol is used with pattern which has
// pre-message or psks.
_, err := babble.NewProtocol("Noise_N_25519_ChaChaPoly_BLAKE2s", "Demo", true)
fmt.Println(err)  // missing key: remote static key

_, err := babble.NewProtocol("Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s", "Demo", true)
fmt.Println(err)  // psk mode: expected to have 1 psks, got 0
```

Patterns supported using `NewProtocol`,

- `NN`
- `NX`, `NX1`
- `XN`, `X1N`
- `IN`, `I1N`
- `XX`, `X1X`, `XX1`, `X1X1`
- `IX`, `I1X`, `IX1`, `I1X1`

For full support, use `NewProtocolWithConfig` instead.



### NewProtocolWithConfig

```go
func NewProtocolWithConfig(config *ProtocolConfig) (*HandshakeState, error)
```

`NewProtocolWithConfig` takes a `*ProtocolConfig` to create a handshake state.

```go
// create a config first
cfg := &babble.ProtocolConfig{
    Name: "Noise_NN_25519_ChaChaPoly_BLAKE2s",
    Initiator: true,
    Prologue: "Demo",
}

// use the config to construct a handshake state.
// this is equivalent of calling
// NewProtocol("Noise_NN_25519_ChaChaPoly_BLAKE2s", "Demo", true)
p, _ := babble.NewProtocolWithConfig(cfg)
```



Specifying a local static private key and a remote static public key,

```go
// decode hex into binary, note that the local static key(s) is a private key, and the remote static key(rs) is a public key.
s, _ := hex.DecodeString(
  "a8abababababababababababababababababababababababababababababab6b")
rs, _ := hex.DecodeString(
  "c3c637648530e306e1115428acc44d0f0502615ee23ec1de0e59c5a148e9a30d")

cfg := &babble.ProtocolConfig{
    Name:            "Noise_KK_25519_ChaChaPoly_BLAKE2s",
    Initiator:       true,
    Prologue:        "Demo",
    LocalStaticPriv: s,
    RemoteStaticPub: rs,
}
p, _ := babble.NewProtocolWithConfig(cfg)
```



Specifying PSKs,

```go
// decode hex into binary
psk0, _ := hex.DecodeString(
  "c3c637648530e306e1115428acc44d0f0502615ee23ec1de0e59c5a148e9a30d")
psk1, _ := hex.DecodeString(
  "2d0326b5ea11ba9330949dc4e816735615d718551aa9e777f25941c95d7899eb")
// put psks into a slice
psks := [][]byte{psk0, psk1}

cfg := &babble.ProtocolConfig{
    Name: "Noise_NNpsk0+psk1_25519_ChaChaPoly_BLAKE2s",
    Initiator: true,
    Prologue: "Demo",
    Psks: psks,
}
p, _:= babble.NewProtocolWithConfig(cfg)
```



Specifying default Rekey behavior,

```go
// This config will set the rekeyer to rotate the cipher key every
// 1000 messages and won't reset the nonce.
rkCfg := &babble.DefaultRekeyerConfig{
    Interval: 1000,
    ResetNonce: false,
}

cfg := &babble.ProtocolConfig{
    Name: "Noise_NN_25519_ChaChaPoly_BLAKE2s",
    Initiator: true,
    Prologue: "Demo",
    RekeyerConfig: rkCfg,
}
p, _ := babble.NewProtocolWithConfig(cfg)
```

You can also specify a customized `rekeyer` by defining your own rules on when and how the cipher key should be reset. Read [this documentation](rekey) for more details.

Check [here](https://pkg.go.dev/github.com/yyforyongyu/babble?tab=doc#ProtocolConfig) for the full list of parameters in the  `ProtocolConfig`.



### GetInfo

Once created, the `GetInfo` method can be handy to monitor the internal state of the current handshake.

```go
// GetInfo will return the internal state info of the handshake
info, _ := p.GetInfo()
fmt.Printf("%s", info)
```

which prints the following result,

```json
{
	"chaining_key": "38a1b63073db5d5a3a4007b51e83c41598ea2f67e2389e121c56f3a1462d98aa",
	"cipher_key": "0000000000000000000000000000000000000000000000000000000000000000",
	"digest": "ec62085a3ed4240d70240150cc3f98a170fd781cf11c151c65776b04e67be173",
	"finished": false,
	"initiator": true,
	"key_pair": {
		"local_static_priv": "",
		"local_static_pub": "",
		"local_ephemeral_priv": "",
		"local_ephemeral_pub": "",
		"remote_ephemeral_pub": "",
		"remote_static_pub": ""
	},
	"nonce": 0,
	"pattern": {
		"psk_mode": {
			"mode": false,
			"psks": {}
		},
		"name": "NN",
		"pre_message": {},
		"message": {
			"0": "->, e",
			"1": "<-, e, ee"
		},
		"index_processed": -1
	},
	"prologue": "Demo",
	"send_cipher": {
		"key": "",
		"nonce": 0
	},
	"recv_cipher": {
		"key": "",
		"nonce": 0
	},
	"rekey": {
		"interval": 10000,
		"reset_nonce": true
	}
}
```



### Performing handshakes

The following code gives an example for how two participants, Alice and Bob, performs a handshake using the handshake pattern `NN`.

```go
// Pattern used here is NN,
// -> e,
// <- e, ee

// alice is the initiator
alice, _ := babble.NewProtocol("Noise_NN_25519_ChaChaPoly_BLAKE2s", "Demo", true)
// bob is the responder
bob, _ := babble.NewProtocol("Noise_NN_25519_ChaChaPoly_BLAKE2s", "Demo", false)

// alice writes the first message, -> e
ciphertext, err := alice.WriteMessage(nil)
if err != nil {
    fmt.Println("alice: -> e, gives an error", err)
}
// bob reads the first message, ->
_, err = bob.ReadMessage(ciphertext)
if err != nil {
    fmt.Println("bob: -> e, gives an error", err)
}

// bob writes the second message, <- e, ee
ciphertext, err = bob.WriteMessage(nil)
if err != nil {
    fmt.Println("bob: <- e, ee, gives an error", err)
}
// alice reads the second message, <- e, ee
_, err = alice.ReadMessage(ciphertext)
if err != nil {
    fmt.Println("alice: <- e, ee, gives an error", err)
}

// the handshake is finished, we can verify that,
fmt.Println("alice's handshake is finished: ", alice.Finished())
fmt.Println("bob's handshake is finished: ", bob.Finished())
```

The full example can be found at [examples/handshake](examples/handshake/main.go).



# Extentable Components

Aside from the built-in components, it's pretty straightforward to add new components to the framework using the `Register` method defined in each component's package. For instance, to add a new pattern,

```go
import "github.com/yyforyongyu/babble/pattern"

// Register a dumb pattern
name := "YY"
rawPattern := `
  -> e
  <- e, ee, es`

// Register will validate the pattern, if invalid, an error is returned.
_ := pattern.Register(name, rawPattern)

// Now "YY" is a valid pattern name, and it can be used in the protocol name as,
p, _ := babble.NewProtocol("Noise_YY_25519_ChaChaPoly_BLAKE2s", "Demo", true)
```

You can check the package documentation for details on how to implement new components.

- [Cipher](cipher). To add a new cipher, implement the `AEAD interface`.
- [Hash](hash). To add a new hash, implement the `Hash interface`.
- [DH](dh). To add a new DHKE, implement the `Curve interface`.
- [Pattern](pattern). To add a new pattern, simply provide the pattern in string.



# Vector tests

See [vector documentation](vectors) for more details.

