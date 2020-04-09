package dh

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec"
)

// DHLENBitcoin defines the DHLEN for Secp256k1.
const DHLENBitcoin = 32

// Secp256k1 implements the DH interface for the Bitcoin curve.
var Secp256k1 Curve = &CurveBitcoin{DHLEN: DHLENBitcoin}

// PublicKeyBitcoin implements the PublicKey interface.
type PublicKeyBitcoin struct {
	// btcecPub mounts a btcec.PublicKey
	*btcec.PublicKey
}

// Bytes turns the underlying bytes array into a slice.
func (pk *PublicKeyBitcoin) Bytes() []byte {
	return pk.SerializeCompressed()
}

// Hex returns the public key in hexstring.
func (pk *PublicKeyBitcoin) Hex() string {
	return hex.EncodeToString(pk.Bytes())
}

// PrivateKeyBitcoin implements the PrivateKey interface.
type PrivateKeyBitcoin struct {
	// btcecPriv mounts a btcec.PrivateKey
	*btcec.PrivateKey
	pub *PublicKeyBitcoin
}

// Bytes turns the underlying bytes array into a slice.
func (pk *PrivateKeyBitcoin) Bytes() []byte {
	return pk.Serialize()
}

// DH performs a Diffie-Hellman calculation between the private key in the
// key pair and the public key.
func (pk *PrivateKeyBitcoin) DH(pub PublicKey) ([]byte, error) {
	// replace the interface's value for public key
	pubKey, ok := pub.(*PublicKeyBitcoin)
	if !ok {
		return nil, ErrMismatchedPublicKey
	}

	var shared [DHLENBitcoin]byte

	newPoint := &btcec.PublicKey{}
	x, y := btcec.S256().ScalarMult(
		pubKey.X, pubKey.Y, pk.D.Bytes())
	newPoint.X = x
	newPoint.Y = y

	shared = sha256.Sum256(newPoint.SerializeCompressed())
	return shared[:], nil
}

// PubKey returns the corresponding public key.
func (pk *PrivateKeyBitcoin) PubKey() PublicKey {
	return pk.pub
}

// Update writes secret to the private key.
func (pk *PrivateKeyBitcoin) Update(data []byte) {
	// construct the key pairs
	priv, pub := btcec.PrivKeyFromBytes(btcec.S256(), data)
	// assign the values
	pk.PrivateKey = priv
	pk.pub = &PublicKeyBitcoin{pub}
}

// CurveBitcoin implements the DH interface(aka "Secp256k1").
type CurveBitcoin struct {
	DHLEN int
}

// GenerateKeyPair creates a key pair from entropy. If the entropy is not
// supplied, it will use rand.Read to generate a new private key.
func (dh *CurveBitcoin) GenerateKeyPair(entropy []byte) (PrivateKey, error) {
	secret := make([]byte, DHLENBitcoin)

	if entropy != nil {
		// entropy is given, use it to create the private key.
		copy(secret, entropy[:DHLENBitcoin])
	} else {
		// no entropy given, use the default rand.Read.
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
	}

	pk := &PrivateKeyBitcoin{pub: &PublicKeyBitcoin{}}
	pk.Update(secret)

	return pk, nil
}

// Size returns the DHLEN.
func (dh *CurveBitcoin) Size() int {
	return dh.DHLEN
}

func (dh *CurveBitcoin) String() string {
	return "secp256k1"
}

func init() {
	Register(Secp256k1.String(), Secp256k1)
}
