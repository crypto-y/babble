// This is an implemention for demonstration only.
package main

import (
	"fmt"

	"github.com/yyforyongyu/babble"
)

func main() {
	// Pattern used here is NN,
	// -> e,
	// <- e, ee

	// alice is the initiator
	alice, _ := babble.NewProtocol(
		"Noise_NN_25519_ChaChaPoly_BLAKE2s", "Demo", true)
	// bob is the responder
	bob, _ := babble.NewProtocol(
		"Noise_NN_25519_ChaChaPoly_BLAKE2s", "Demo", false)

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

	// we can check the info to see their internal states
	aliceInfo, _ := alice.GetInfo()
	fmt.Println(string(aliceInfo))
	bobInfo, _ := bob.GetInfo()
	fmt.Println(string(bobInfo))

	// alice and bob can now exchange messages using their cipherstates.

	// alice sends message to bob
	plaintextA := []byte("a text from alice")
	ciphertextA, err := alice.SendCipherState.EncryptWithAd(nil, plaintextA)
	if err != nil {
		fmt.Println("alice failed to encrypt")
	}
	plaintextB, err := bob.RecvCipherState.DecryptWithAd(nil, ciphertextA)
	if err != nil {
		fmt.Println("bob failed to encrypt")
	}
	fmt.Printf("alice sent: %s\nbob decrypted: %s\n", plaintextA, plaintextB)

	// bob sends message to alice
	plaintextB = []byte("a text from bob")
	ciphertextB, err := bob.SendCipherState.EncryptWithAd(nil, plaintextB)
	if err != nil {
		fmt.Println("bob failed to encrypt")
	}
	plaintextA, err = alice.RecvCipherState.DecryptWithAd(nil, ciphertextB)
	if err != nil {
		fmt.Println("alice failed to encrypt")
	}
	fmt.Printf("bob sent: %s\nalice decrypted: %s\n", plaintextB, plaintextA)
}
