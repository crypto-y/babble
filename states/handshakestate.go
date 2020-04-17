package noise

import (
	"errors"
	"fmt"

	"github.com/yyforyongyu/noise/dh"
	"github.com/yyforyongyu/noise/pattern"
)

var (
	errProtocolNameInvalid  = errors.New("protocol name is too long")
	errPatternIndexOverflow = errors.New("pattern index overflow")
	errInvalidPayload       = errors.New("invalid payload size")
)

// handshakeState object contains a symmetricState plus DH variables
// (s, e, rs, re) and a variable representing the handshake pattern. During the
// handshake phase each party has a single handshakeState, which can be deleted
// once the handshake is finished.
type handshakeState struct {
	handshakePattern *pattern.HandshakePattern
	ss               symmetricState

	// The local static key pair, s in the noise specs.
	localStatic dh.PrivateKey

	// The local ephemeral key pair, e in the noise specs.
	localEphemeral dh.PrivateKey

	// The remote party's static public key, rs in the noise specs.
	remoteStaticPub dh.PublicKey

	// The remote party's ephemeral public key, re in the noise specs.
	remoteEphemeralPub dh.PublicKey

	// A boolean indicating the initiator or responder role.
	initiator bool

	// patternIndex keeps a track of the handshake patterns processed. It's
	// value is between 0 and len(handshakePattern.MessagePattern)-1
	patternIndex int

	readCipherState  *cipherState
	writeCipherState *cipherState

	psk []byte
}

// Initialize takes a valid handshakePattern and an initiator boolean
// specifying this party's role as either initiator or responder. It takes,
//  - a prologue byte sequence which may be zero-length, or which may contain
//    context information that both parties want to confirm is identical.
//  - a set of DH key pairs (localStatic, localEphemeral) and public keys
//    (remoteStaticPub, remoteEphemeralPub) for initializing local variables,
//    any of which may be empty. Public keys are only passed in if the
//    handshakePattern uses pre-messages. The ephemeral values (localEphemeral,
//    remoteEphemeralPub) are typically left empty, since they are created and
//    exchanged during the handshake; but there are exceptions when using
//    compound protocols.
func (hs *handshakeState) Initialize(
	protocolName, prologue []byte, initiator bool,
	hp *pattern.HandshakePattern,
	s, e dh.PrivateKey,
	rs, re dh.PublicKey) error {
	// Protocol name must be 255 bytes or less
	if len(protocolName) > 255 {
		return errProtocolNameInvalid
	}

	// Calls InitializeSymmetric(protocolName).
	hs.ss.InitializeSymmetric(protocolName)

	// Calls MixHash(prologue).
	hs.ss.MixHash(prologue)

	// Sets the initiator, localStatic, localEphemeral, remoteStaticPub, and
	// remoteEphemeralPub variables to the corresponding arguments.
	hs.initiator = initiator
	hs.localStatic = s
	hs.localEphemeral = e
	hs.remoteStaticPub = rs
	hs.remoteEphemeralPub = re
	hs.handshakePattern = hp

	hs.processPreMessage()

	return nil
}

// ReadMessage takes a byte sequence containing a Noise handshake message, and a
// payload_buffer to write the message's plaintext payload into.
func (hs *handshakeState) ReadMessage(message, payloadBuffer []byte) error {
	// find the right pattern line
	//
	// first, check the patternIndex is right
	if len(hs.handshakePattern.MessagePattern)-1 < hs.patternIndex {
		return errPatternIndexOverflow
	}
	line := hs.handshakePattern.MessagePattern[hs.patternIndex]
	// second, check the direction is right. If the first token is "->", then
	// the message is sent from the initiator to the responder, so it must be
	// read by a responder, otherwise an initiator.
	//
	// if hs.initiator is false, then it's read by a responder.
	// if the first token is TokenInitiator, then it's "->".
	// thus it's a valid pattern which should be processed.
	if hs.initiator == (line[0] == pattern.TokenInitiator) {
		return errInvalidDirection("ReadMessage: ", hs.initiator, line[0])
	}

	var err error
	for _, token := range line {
		message, err = hs.processReadToken(string(token), message)
		if err != nil {
			return err
		}
	}

	// Now calls DecryptAndHash() on the remaining bytes of the message and
	// stores the output into payloadBuffer.
	plaintext, err := hs.ss.DecryptAndHash(message)
	if err != nil {
		return err
	}
	copy(payloadBuffer, plaintext)

	hs.patternIndex++
	if hs.patternIndex < len(hs.handshakePattern.MessagePattern) {
		return nil
	}

	// when finished, returns two new CipherState objects by calling Split().
	c1, c2, err := hs.ss.Split()
	if err != nil {
		return err
	}
	hs.readCipherState = c1
	hs.writeCipherState = c2

	return nil
}

// WriteMessage takes a payload byte sequence which may be zero-length, and a
// messageBuffer to write the output into.
func (hs *handshakeState) WriteMessage(payload, messageBuffer []byte) error {
	// find the right pattern line
	//
	// first, check the patternIndex is right
	if len(hs.handshakePattern.MessagePattern)-1 < hs.patternIndex {
		return errPatternIndexOverflow
	}
	line := hs.handshakePattern.MessagePattern[hs.patternIndex]
	// second, check the direction is right. If the first token is "->", then
	// the message is sent from the initiator to the responder, so it must be
	// written by an initiator, otherwise a responder.
	//
	// if hs.initiator is true, then it's written by an initiator.
	// if the first token is TokenInitiator, then it's "->".
	// thus it's a valid pattern which should be processed.
	if hs.initiator != (line[0] == pattern.TokenInitiator) {
		return errInvalidDirection("WriteMessage: ", hs.initiator, line[0])
	}

	for _, token := range line {
		if err := hs.processWriteToken(string(token), payload); err != nil {
			return err
		}
	}

	// Appends EncryptAndHash(payload) to the buffer.
	ciphertext, err := hs.ss.EncryptAndHash(payload)
	if err != nil {
		return err
	}
	copy(messageBuffer, ciphertext)

	hs.patternIndex++
	if hs.patternIndex < len(hs.handshakePattern.MessagePattern) {
		return nil
	}

	// when finished, returns two new CipherState objects by calling Split().
	c1, c2, err := hs.ss.Split()
	if err != nil {
		return err
	}
	hs.writeCipherState = c1
	hs.readCipherState = c2

	return nil
}

// processPreMessage calls MixHash() once for each public key listed in the
// pre-messages from handshakePattern, with the specified public key as input.
//
// If both initiator and responder have pre-messages, the initiator's public
// keys are hashed first. If multiple public keys are listed in either party's
// pre-message, the public keys are hashed in the order that they are listed.
func (hs *handshakeState) processPreMessage() {
	// PreMessagePattern is a paragraph in format,
	// -> s
	// <- s
	for _, line := range hs.handshakePattern.PreMessagePattern {
		// pattern is a line in format,
		// -> s
		for _, token := range line {
			switch token {
			case pattern.TokenE:
				hs.ss.MixHash(hs.localEphemeral.PubKey().Bytes())
				// if psk
				// hs.ss.MixKey(hs.localEphemeral.publicKey)
			case pattern.TokenS:
				hs.ss.MixHash(hs.localStatic.PubKey().Bytes())
			}
		}
	}
}

func (hs *handshakeState) processReadToken(
	token string, payload []byte) ([]byte, error) {
	var err error
	switch token {
	case "e":
		payload, err = hs.readTokenE(payload)
		if err != nil {
			return nil, err
		}
	case "s":
		payload, err = hs.readTokenS(payload)
		if err != nil {
			return nil, err
		}
	// case "psk":
	// 	hs.ss.MixKeyAndHash(hs.psk)
	default:
		if err := hs.processTokenDH(string(token)); err != nil {
			return nil, err
		}
	}
	return payload, err
}

func (hs *handshakeState) processWriteToken(
	token string, payload []byte) error {
	var err error
	switch token {
	case "e":
		if err := hs.writeTokenE(payload); err != nil {
			return err
		}
	case "s":
		if err := hs.writeTokenS(payload); err != nil {
			return err
		}
	// case "psk":
	// 	hs.ss.MixKeyAndHash(hs.psk)
	default:
		if err := hs.processTokenDH(string(token)); err != nil {
			return err
		}
	}
	return err
}

func (hs *handshakeState) readTokenE(payload []byte) ([]byte, error) {
	// Sets re (which must be empty) to the next DHLEN bytes from the
	// payload. Calls MixHash(re.publicKey).

	// check empty

	dhlen := hs.ss.curve.Size()
	if len(payload) < dhlen {
		return nil, errInvalidPayload
	}
	hs.remoteEphemeralPub.LoadBytes(payload[:dhlen])
	hs.ss.MixHash(hs.remoteEphemeralPub.Bytes())
	return payload[dhlen:], nil
}

func (hs *handshakeState) writeTokenE(payload []byte) error {
	// Sets e (which must be empty) to GENERATE_KEYPAIR(). Appends e.public_key
	// to the buffer. Calls MixHash(e.public_key).
	key, err := hs.ss.curve.GenerateKeyPair(nil)
	if err != nil {
		return err
	}
	hs.localEphemeral = key
	payload = append(payload, hs.localEphemeral.PubKey().Bytes()...)

	hs.ss.MixHash(hs.localStatic.PubKey().Bytes())
	return nil
}

func (hs *handshakeState) readTokenS(payload []byte) ([]byte, error) {
	// Sets temp to the next DHLEN + 16 bytes of the payload if
	// HasKey() == True, or to the next DHLEN bytes otherwise. Sets
	// rs (which must be empty) to DecryptAndHash(temp).
	dhlen := hs.ss.curve.Size()
	adlen := hs.ss.cs.cipher.Cipher().Overhead()
	var temp []byte
	tempLen := dhlen
	if hs.ss.cs.HasKey() {
		tempLen = dhlen + adlen
	}
	copy(temp, payload[:tempLen])
	data, err := hs.ss.DecryptAndHash(temp)
	if err != nil {
		return nil, err
	}
	hs.remoteStaticPub.LoadBytes(data)
	return payload[tempLen:], nil

}

func (hs *handshakeState) writeTokenS(payload []byte) error {
	// Appends EncryptAndHash(s.public_key) to the buffer.
	data, err := hs.ss.EncryptAndHash(hs.localStatic.PubKey().Bytes())
	if err != nil {
		return err
	}
	payload = append(payload, data...)
	return nil
}

func (hs *handshakeState) processTokenDH(token string) error {
	var local dh.PrivateKey
	var remote dh.PublicKey

	switch token {
	case "ee":
		local = hs.localEphemeral      // e
		remote = hs.remoteEphemeralPub // re
	case "ss":
		local = hs.localStatic      // s
		remote = hs.remoteStaticPub // rs
	case "es":
		if hs.initiator {
			local = hs.localEphemeral   // e
			remote = hs.remoteStaticPub // rs
		} else {
			local = hs.localStatic         // s
			remote = hs.remoteEphemeralPub // re
		}
	case "se":
		if hs.initiator {
			local = hs.localStatic         // s
			remote = hs.remoteEphemeralPub // re
		} else {
			local = hs.localEphemeral   // e
			remote = hs.remoteStaticPub // rs
		}
	}

	digest, err := local.DH(remote.Bytes())
	if err != nil {
		return err
	}
	hs.ss.MixKey(digest)
	return nil
}

func errInvalidDirection(format string, intiator bool, a ...interface{}) error {
	role := "responder"
	if intiator {
		role = "initiator"
	}
	suffix := role + " cannot process line begins with %s"
	return fmt.Errorf(format+suffix, a...)
}
