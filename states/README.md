# Rekey

It's up to the application to decide whether and when to perform rekey. 

From the [noise specs](https://noiseprotocol.org/noise.html#rekey),

>It is up to to the application if and when to perform rekey. For example:
>
>- Applications might perform **continuous rekey**, where they rekey the relevant cipherstate after every transport message sent or received. This is simple and gives good protection to older ciphertexts, but might be difficult for implementations where changing keys is expensive.
>- Applications might rekey a cipherstate automatically after it has has been used to send or receive some number of messages.
>- Applications might choose to rekey based on arbitrary criteria, in which case they signal this to the other party by sending a message.
>
>Applications must make these decisions on their own; there are no pattern modifiers which specify rekey behavior.

A `Rekeyer` interface is created to help manage rekey, with a `defaultRekeyer` as a built-in manager.

rekey, when, how, and relationship with nonce?


Nonce