package main

import (
	"encoding/hex"
	"fmt"

	"github.com/yyforyongyu/babble"
)

func main() {
	// returns an error if the NewProtocol is used with pattern which has
	// pre-message or psks.
	_, err := babble.NewProtocol(
		"Noise_N_25519_ChaChaPoly_BLAKE2s", "Demo", true)
	fmt.Println(err)

	// creates a new handshake state using pattern NN, curve 25519, cipher
	// ChaChaPoly and hash function BLAKE2s.
	p, _ := babble.NewProtocol(
		"Noise_NN_25519_ChaChaPoly_BLAKE2s", "Demo", true)

	// GetInfo will return the internal state info of the handshake
	info, _ := p.GetInfo()
	fmt.Printf("%s", info)

	// decode hex into binary
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
	p1, _ := babble.NewProtocolWithConfig(cfg)
	info1, _ := p1.GetInfo()
	fmt.Printf("%s", info1)
}
