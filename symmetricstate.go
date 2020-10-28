package babble

import (
	"errors"

	noiseCipher "github.com/crypto-y/babble/cipher"
	"github.com/crypto-y/babble/dh"
	"github.com/crypto-y/babble/hash"
	"golang.org/x/crypto/hkdf"
)

var (
	errInvalidHKDFNum     = errors.New("HKDF num must be 2 or 3")
	errInvalidKeySize     = errors.New("key size must be 0, 32, or DHLEN")
	errInvalidChainingKey = errors.New("chaining key size invalid")
)

// symmetricState object contains a CipherState plus ck and h variables. It is
// so-named because it encapsulates all the "symmetric crypto" used by Noise.
// During the handshake phase each party has a single symmetricState, which can
// be deleted once the handshake is finished.
type symmetricState struct {
	cs    *CipherState
	hash  hash.Hash
	curve dh.Curve

	// A chaining key of HASHLEN bytes.
	//
	// chainingKey is the ck in the noise specs.
	chainingKey []byte

	// A hash output of HASHLEN bytes.
	//
	// digest is the h in the noise specs.
	digest []byte
}

// DecryptAndHash sets plaintext = DecryptWithAd(digest, ciphertext), calls
// MixHash(ciphertext), and returns plaintext. Note that if cipherKey is empty,
// the DecryptWithAd() call will set plaintext equal to ciphertext.
func (s *symmetricState) DecryptAndHash(ciphertext []byte) ([]byte, error) {
	plaintext, err := s.cs.DecryptWithAd(s.digest, ciphertext)
	if err != nil {
		return nil, err
	}

	s.MixHash(ciphertext)

	return plaintext, nil
}

// EncryptAndHash sets ciphertext = EncryptWithAd(digest, plaintext),
// calls MixHash(ciphertext), and returns ciphertext. Note that if key is
// empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
func (s *symmetricState) EncryptAndHash(plaintext []byte) ([]byte, error) {
	ciphertext, err := s.cs.EncryptWithAd(s.digest, plaintext)
	if err != nil {
		return nil, err
	}

	s.MixHash(ciphertext)

	return ciphertext, nil
}

// GetHandshakeHash returns hash digest. This function should only be called
// at the end of a handshake, i.e. after the Split() function has been called.
// This function is used for channel binding,
func (s *symmetricState) GetHandshakeHash() []byte {
	return s.digest
}

// HKDF returns [num] of byte sequences each of length HASHLEN. It uses the
// chainingKey, secret, and num, in which,
//  - chainingKey must be byte sequence of length HASHLEN
//  - secret must be byte sequence with length either zero, 32, or DHLEN bytes.
//  - num must be 2 or 3.
func (s *symmetricState) HKDF(secret []byte, num int) ([][]byte, error) {
	// first, validate num
	if num != 2 && num != 3 {
		return nil, errInvalidHKDFNum
	}

	// then, validate the secret size
	if len(secret) != 0 &&
		len(secret) != 32 &&
		len(secret) != s.curve.Size() {
		return nil, errInvalidKeySize
	}

	// check chainingKey is HASHLEN
	if len(s.chainingKey) != s.hash.HashLen() {
		return nil, errInvalidChainingKey
	}

	// A concept remapping
	//  - salt is the chaining key
	//  - info is an empty byte slice([]byte)
	h := hkdf.New(s.hash.New, secret, s.chainingKey, ZEROLEN)

	// read [num] outputs
	var result [][]byte
	for i := 0; i < num; i++ {
		output := make([]byte, s.hash.HashLen())

		n, err := h.Read(output)
		if err != nil {
			return nil, err
		}
		// return an error if not full HASHLEN bytes are read
		if n != s.hash.HashLen() {
			return nil, errors.New("HKDF cannot read full HASHLEN bytes")
		}

		result = append(result, output)
	}
	return result, nil
}

// InitializeSymmetric takes an arbitrary-length protocolName byte sequence.
// Executes the following steps:
// 	- If protocolName is less than or equal to HASHLEN bytes in length, sets
// 	  hashOutput equal to protocolName with zero bytes appended to make HASHLEN
// 	  bytes. Otherwise sets hashOutput = HASH(protocolName).
// 	- Sets chainingKey = hashOutput.
// 	- Calls initializeKey(empty).
func (s *symmetricState) InitializeSymmetric(protocolName []byte) {
	// TODO: my understanding is that when the protocolName's size is less than
	// HASHLEN, we should pad zeros to it, then hash it.
	// However it seems that the original protocol suggests that we just use the
	// padded HASHLEN bytes without hashing it afterwards?
	if len(protocolName) <= s.hash.HashLen() {
		s.digest = make([]byte, s.hash.HashLen())
		copy(s.digest, protocolName)
	} else {
		h := s.hash.New()
		_, _ = h.Write(protocolName)
		s.digest = h.Sum(nil)
	}

	s.chainingKey = make([]byte, s.hash.HashLen())
	copy(s.chainingKey, s.digest)
	_ = s.cs.initializeKey(ZEROS)
}

// MixHash sets h = HASH(h || data) and writes it to digest.
func (s *symmetricState) MixHash(data []byte) {

	h := s.hash.New()

	_, _ = h.Write(s.digest)
	_, _ = h.Write(data)
	s.digest = h.Sum(nil)

	h.Reset()
}

// MixKey executes the following steps:
// 	- Sets chainingKey, tempKey = HKDF(chainingKey, keyMaterial, 2).
// 	- If HASHLEN is 64, then truncates tempKey to 32 bytes.
// 	- Calls initializeKey(tempKey).
func (s *symmetricState) MixKey(keyMaterial []byte) error {
	var tempKey [CipherKeySize]byte

	digests, err := s.HKDF(keyMaterial, 2)
	if err != nil {
		return err
	}

	s.chainingKey = digests[0]
	// because tempKey is fixed size 32-byte array, it will automatically
	// truncate if HASHLEN is 64.
	copy(tempKey[:], digests[1])

	if err := s.cs.initializeKey(tempKey); err != nil {
		return err
	}
	return nil
}

// MixKeyAndHash is used for handling pre-shared symmetric keys, it executes the
// following steps:
// 	- Sets chainingKey, tempHashOutput, tempKey =
// 		HKDF(chainingKey, keyMaterial, 3).
// 	- Calls MixHash(tempHashOutput).
// 	- If HASHLEN is 64, then truncates tempKey to 32 bytes.
// 	- Calls initializeKey(tempKey).
func (s *symmetricState) MixKeyAndHash(keyMaterial []byte) error {
	digests, err := s.HKDF(keyMaterial, 3)
	if err != nil {
		return err
	}

	var tempKey [CipherKeySize]byte

	s.chainingKey = digests[0]
	tempHashOutput := digests[1]
	// because tempKey is fixed size 32-byte array, it will automatically
	// truncate if HASHLEN is 64.
	copy(tempKey[:], digests[2])
	s.MixHash(tempHashOutput)
	if err := s.cs.initializeKey(tempKey); err != nil {
		return err
	}

	return nil
}

// Reset sets the symmetric state's chaining key and hash digest to be nil, and
// calling Reset on related cipher state, curve and hash.
func (s *symmetricState) Reset() {
	s.chainingKey = nil
	s.digest = nil

	if s.cs != nil {
		s.cs.Reset()
		s.cs = nil
	}
}

// Split returns a pair of CipherState structs for encrypting transport
// messages. Executes the following steps,
// 	- Sets tempKey1, tempKey2 = HKDF(zerolen, 2).
// 	- If HASHLEN is 64, then truncates tempKey1 and tempKey2 to 32 bytes.
// 	- Creates two new CipherState instances c1 and c2.
// 	- Calls c1.initializeKey(tempKey1) and c2.initializeKey(tempKey2).
// 	- Returns the pair (c1, c2).
func (s *symmetricState) Split() (c1, c2 *CipherState, err error) {
	digests, err := s.HKDF(ZEROLEN, 2)
	if err != nil {
		return nil, nil, err
	}

	var tempKey1 [CipherKeySize]byte
	var tempKey2 [CipherKeySize]byte
	copy(tempKey1[:], digests[0])
	copy(tempKey2[:], digests[1])

	cipher1, _ := noiseCipher.FromString(s.cs.cipher.String())
	cipher2, _ := noiseCipher.FromString(s.cs.cipher.String())

	c1 = newCipherState(cipher1, s.cs.RekeyManger)
	c2 = newCipherState(cipher2, s.cs.RekeyManger)

	if err := c1.initializeKey(tempKey1); err != nil {
		return nil, nil, err
	}
	if err := c2.initializeKey(tempKey2); err != nil {
		return nil, nil, err
	}

	return c1, c2, nil
}

func newSymmetricState(
	cs *CipherState, h hash.Hash, c dh.Curve) *symmetricState {
	ss := &symmetricState{
		cs:    cs,
		hash:  h,
		curve: c,
	}
	return ss
}
