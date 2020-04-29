# Rekey

Package rekey defines an interface `Rekeyer` to help manage the rekey process. It's up to the application to decide whether and when to perform rekey. 

From the [noise specs](https://noiseprotocol.org/noise.html#rekey),

>- Applications might perform **continuous rekey**, where they rekey the relevant cipherstate after every transport message sent or received. This is simple and gives good protection to older ciphertexts, but might be difficult for implementations where changing keys is expensive.
>- Applications might rekey a cipherstate automatically after it has has been used to send or receive some number of messages.
>- Applications might choose to rekey based on arbitrary criteria, in which case they signal this to the other party by sending a message.
>
>Applications must make these decisions on their own; there are no pattern modifiers which specify rekey behavior.

###  The `defaultRekeyer` 

`defaultRekeyer` is a built-in manager and can be initiated by calling `NewDefault`, the signature is,

```
func NewDefault(interval uint64, cipher noiseCipher.AEAD, resetNonce bool) Rekeyer
```

The `interval` parameter specifies the number of messages to be encrypted/decrypted before performing rekey. The `resetNonce` determines whether the cipher's nonce is reset to zero when the rekey is performed.

`NewDefault` creates a default rekeyer defined by the noise protocol. It returns a 32-byte key from calling the `Rekey` function defined in the cipher, which is the result of `Encrypt(k, maxnonce, zerolen, zeros)`, where,

- `maxnonce` equals 2^64-1,
- `zerolen` is a zero-length byte sequence,
- `zeros` is a sequence of 32 bytes filled with zeros.

When used by the package babble, if unspecified, a default value of `10000` will be used as `interval`, and `resetNonce` is default to `true`.

### Customized Rekeyer

TODO



### Nonce

When deciding to reset the nonce or not, a few things to keep in mind,

- Leaving nonce unchanged is simple for rekeyer, while resetting nonce can make handshake state management easier. If the nonce is unset, when reaching the max nonce value allowed, a new handshake must be performed again.
- If the cipher has a weakness such that repeated rekeying gives rise to a cycle of keys, then letting nonce advance will avoid catastrophic reuse of the same key and nonce values.
- Letting nonce advance puts a bound on the total number of encryptions that can be performed with a set of derived keys.