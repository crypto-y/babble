# Noise Handshake Patterns

This package implements the handshake patterns specified in the [noise protocol](https://noiseprotocol.org/noise.html#handshake-patterns).

### Built-in Patterns

There are a total of 38 patterns built, in which,

**[One-way handshake patterns](https://noiseprotocol.org/noise.html#one-way-handshake-patterns)**

3 one-way handskake patterns.

**[Interactive handshake patterns](https://noiseprotocol.org/noise.html#interactive-handshake-patterns-fundamental)**

12 interactive handskake patterns.

**[Deferred handshake patterns](https://noiseprotocol.org/noise.html#interactive-handshake-patterns-deferred)**

23 deferred handshake patterns.



### Customized Handshake Pattern

To create your own handshake pattern, use the function `Register`, pass in the name and pattern in string. Once it passed all the checks, you can then use it by calling `FromString(patternName)`

Check [examples/newpattern](../examples/newpattern/main.go), which implements a new pattern `YY`, once implemented, Once implemented, it can be used via the protocol name,

```go
// Register will validate the pattern, if invalid, an error is returned.
rawPattern := `
		<- s
		-> s
		...
		-> e
		<- e, ee, es`
err := pattern.Register("YY", rawPattern)

// Now "YY" is a valid pattern name, and it can be used in the protocol name as,
p, _ := babble.NewProtocol("Noise_YY_25519_ChaChaPoly_BLAKE2s", "Demo", true)
```

