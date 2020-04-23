package noise

import (
	"testing"

	"github.com/yyforyongyu/noise/cipher"
	noiseCipher "github.com/yyforyongyu/noise/cipher"
	noiseCurve "github.com/yyforyongyu/noise/dh"
	noiseHash "github.com/yyforyongyu/noise/hash"
)

var (
	cipherA, _ = noiseCipher.FromString("AESGCM")
	cipherB, _ = noiseCipher.FromString("AESGCM")
	cipherG, _ = noiseCipher.FromString("ChaChaPoly")

	hashA, _ = noiseHash.FromString("SHA256")
	hashB, _ = noiseHash.FromString("SHA256")
	hashG, _ = noiseHash.FromString("BLAKE2s")

	curveA, _ = noiseCurve.FromString("25519")
	curveB, _ = noiseCurve.FromString("25519")
	curveG, _ = noiseCurve.FromString("secp256k1")

	key = [CipherKeySize]byte{
		0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
	}
	ad = []byte{
		0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
	}
	message  = []byte("Noise Protocol Framework")
	maxNonce = cipher.MaxNonce
)

func TestStates(t *testing.T) {

}
