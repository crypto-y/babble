package noise

import (
	"errors"
	"fmt"

	"github.com/yyforyongyu/noise/dh"
	"github.com/yyforyongyu/noise/pattern"
)

// maxMessageSize defines the max message size in bytes.
const maxMessageSize = 65535

var (
	errInvalidPayload          = errors.New("invalid payload size")
	errInvalidPskSize          = errors.New("invalid psk size")
	errMessageOverflow         = errors.New("message size exceeds 65535-bytes")
	errMissingHandshakePattern = errors.New("missing handshake pattern")
	errMissingSymmetricState   = errors.New("missing symmetric state")
	errPatternIndexOverflow    = errors.New("pattern index overflow")
	errProtocolNameInvalid     = errors.New("protocol name is too long")
	errPskIndexOverflow        = errors.New("psk index overflow")
)

// handshakeState object contains a symmetricState plus DH variables
// (s, e, rs, re) and a variable representing the handshake pattern. During the
// handshake phase each party has a single handshakeState, which can be deleted
// once the handshake is finished.
type handshakeState struct {
	hp *pattern.HandshakePattern
	ss *symmetricState

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

	sendCipherState *cipherState
	recvCipherState *cipherState

	// psks is slice of 32-byte pre-shared symmetric keys provided by the
	// application. pskIndex tracks the psk token processed.
	psks     [][CipherKeySize]byte
	pskIndex int
}

func newHandshakeState(protocolName, prologue []byte, psks [][]byte,
	initiator bool,
	ss *symmetricState, hp *pattern.HandshakePattern,
	s, e dh.PrivateKey, rs, re dh.PublicKey) (*handshakeState, error) {
	// Protocol name must be 255 bytes or less
	if len(protocolName) > 255 {
		return nil, errProtocolNameInvalid
	}

	// must provide symmetric state
	if ss == nil {
		return nil, errMissingSymmetricState
	}
	hs := &handshakeState{ss: ss}

	// must provide handshake pattern
	if hp == nil {
		return nil, errMissingHandshakePattern
	}

	// call built-in initialize
	if err := hs.Initialize(
		protocolName, prologue, initiator,
		hp, s, e, rs, re); err != nil {
		return nil, err
	}

	// validate psk mode
	if hs.hp.Modifier != nil && len(psks) != len(hs.hp.Modifier.PskIndexes) {
		return nil, errMismatchedPsks(len(hs.hp.Modifier.PskIndexes), len(psks))
	}

	// check psk is at least 32-byte if provided
	for _, psk := range psks {
		var key [CipherKeySize]byte
		if len(psk) != 0 && len(psk) < 32 {
			return nil, errInvalidPskSize
		}
		copy(key[:], psk)
		hs.psks = append(hs.psks, key)
	}

	return hs, nil
}

// Finished returns a bool to indicate whether the handshake is done. The
// patternIndex is used to track the index of last processed pattern, when it
// reaches the end, it indicates the patterns have all been processed.
func (hs *handshakeState) Finished() bool {
	return hs.patternIndex == len(hs.hp.MessagePattern)-1
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
	// Calls InitializeSymmetric(protocolName).
	hs.ss.InitializeSymmetric(protocolName)

	// Calls MixHash(prologue).
	hs.ss.MixHash(prologue)

	// Sets the initiator, localStatic, localEphemeral, remoteStaticPub, and
	// remoteEphemeralPub variables to the corresponding arguments.
	hs.initiator = initiator
	hs.localStatic, hs.localEphemeral = s, e
	hs.remoteStaticPub, hs.remoteEphemeralPub = rs, re
	hs.hp = hp

	if err := hs.processPreMessage(); err != nil {
		return err
	}

	return nil
}

// ReadMessage takes a byte sequence containing a Noise handshake message, and a
// payload_buffer to write the message's plaintext payload into.
func (hs *handshakeState) ReadMessage(message, payloadBuffer []byte) error {
	if len(message) > maxMessageSize {
		return errMessageOverflow
	}
	// find the right pattern line
	//
	// first, check the patternIndex is right
	if len(hs.hp.MessagePattern)-1 < hs.patternIndex {
		return errPatternIndexOverflow
	}
	line := hs.hp.MessagePattern[hs.patternIndex]
	// second, check the direction is right, as ReadMessage should only read
	// remote messages.
	//
	// If the first token is "->", then the message is sent from the initiator
	// to the responder, so it must be read by a responder, otherwise an
	// initiator.
	// if hs.initiator is false, then it's read by a responder.
	// if the first token is TokenInitiator, "->", then it's a message to be
	// read by a responder. Thus it's a valid pattern which should be processed.
	if hs.isLocal(line[0]) {
		return errInvalidDirection("ReadMessage: ", hs.initiator, line[0])
	}

	var err error
	for _, token := range line {
		message, err = hs.processReadToken(token, message)
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

	// when finished, increment the pattern index for next round
	if err := hs.incrementPatternIndex(); err != nil {
		return err
	}

	return nil
}

// WriteMessage takes a payload byte sequence which may be zero-length, and a
// messageBuffer to write the output into.
func (hs *handshakeState) WriteMessage(payload, messageBuffer []byte) error {
	// find the right pattern line
	//
	// first, check the patternIndex is right
	if len(hs.hp.MessagePattern)-1 < hs.patternIndex {
		return errPatternIndexOverflow
	}
	line := hs.hp.MessagePattern[hs.patternIndex]
	// second, check the direction is right, as WriteMessage should only write
	// local messages.
	//
	// If the first token is "->", then the message is sent from the initiator
	// to the responder, so it must be written by an initiator, otherwise a
	// responder.
	// if hs.initiator is true, then it's written by an initiator.
	// if the first token is TokenInitiator, "->", then it's a message to be
	// written by an initiator, thus it's a valid pattern which should be
	// processed.
	if !hs.isLocal(line[0]) {
		return errInvalidDirection("WriteMessage: ", hs.initiator, line[0])
	}

	for _, token := range line {
		if err := hs.processWriteToken(token, payload); err != nil {
			return err
		}
	}

	// Appends EncryptAndHash(payload) to the buffer.
	ciphertext, err := hs.ss.EncryptAndHash(payload)
	if err != nil {
		return err
	}
	if len(ciphertext) > maxMessageSize {
		return errMessageOverflow
	}
	copy(messageBuffer, ciphertext)

	// when finished, increment the pattern index for next round
	if err := hs.incrementPatternIndex(); err != nil {
		return err
	}

	return nil
}

// Reset sets every thing to nil value.
func (hs *handshakeState) Reset() {
	hs.psks = nil
	hs.patternIndex = 0
	hs.initiator = false
	hs.hp = nil
	hs.localStatic, hs.localEphemeral = nil, nil
	hs.remoteStaticPub, hs.remoteEphemeralPub = nil, nil

	if hs.ss != nil {
		hs.ss.Reset()
		hs.ss = nil
	}

	if hs.sendCipherState != nil {
		hs.sendCipherState.Reset()
		hs.sendCipherState = nil
	}

	if hs.recvCipherState != nil {
		hs.recvCipherState.Reset()
		hs.recvCipherState = nil
	}
}

func errInvalidDirection(format string, intiator bool, a ...interface{}) error {
	role := "responder"
	if intiator {
		role = "initiator"
	}
	suffix := role + " cannot process line begins with %s"
	return fmt.Errorf(format+suffix, a...)
}

func errKeyNotEmpty(s string) error {
	return fmt.Errorf("%s is not empty", s)
}

func errMismatchedPsks(want, got int) error {
	return fmt.Errorf("psk mode: expected to have %v psks, got %v", want, got)
}

func errMissingKey(s string) error {
	return fmt.Errorf("pre-message: missing key %s", s)
}

func (hs *handshakeState) incrementPatternIndex() error {
	hs.patternIndex++
	if !hs.Finished() {
		return nil
	}

	// when finished, returns two new CipherState objects by calling Split().
	c1, c2, err := hs.ss.Split()
	if err != nil {
		return err
	}
	hs.sendCipherState = c1
	hs.recvCipherState = c2

	return nil
}

// isLocal checks whether a function is calling from a local view. If a message
// pattern starts with "->", and the caller is an initiator, then it's a local
// view, otherwise it's a remote view. This is useful when deciding whether a
// local or remote ephemeral/static key should be used. For instance,
// when processing a pattern line, "-> s",
//  - if the caller is an initiator, then the local static key should be used;
//  - if the caller is an responder, then the remote static key should be used.
// when performing reading/writing on this pattern,
//  - if the caller is an initiator, it is not allowed to read this line;
//  - if the caller is an responder, it is not allowed to write this line.
func (hs *handshakeState) isLocal(t pattern.Token) bool {
	return hs.initiator == (t == pattern.TokenInitiator)
}

// processPreMessage calls MixHash() once for each public key listed in the
// pre-messages from handshakePattern, with the specified public key as input.
//
// If both initiator and responder have pre-messages, the initiator's public
// keys are hashed first. If multiple public keys are listed in either party's
// pre-message, the public keys are hashed in the order that they are listed.
func (hs *handshakeState) processPreMessage() error {
	// PreMessagePattern is a paragraph in format,
	// -> s
	// <- s
	for _, line := range hs.hp.PreMessagePattern {
		// pattern is a line in format,
		// -> s
		for _, token := range line {

			var keyBytes []byte
			direction := line[0]

			switch token {
			case pattern.TokenE:
				// find out whether a local or remote key to be used
				if hs.isLocal(direction) {
					if hs.localEphemeral == nil {
						return errMissingKey("local ephemeral")
					}
					keyBytes = hs.localEphemeral.PubKey().Bytes()
				} else {
					if hs.remoteEphemeralPub == nil {
						return errMissingKey("remote ephemeral")
					}
					keyBytes = hs.remoteEphemeralPub.Bytes()
				}

				hs.ss.MixHash(keyBytes)
				// if psk enabled, call MixKey
				if hs.hp.Modifier.PskMode() {
					hs.ss.MixKey(keyBytes)
				}

			case pattern.TokenS:
				// find out whether a local or remote key to be used
				if hs.isLocal(direction) {
					if hs.localStatic == nil {
						return errMissingKey("local static")
					}
					keyBytes = hs.localStatic.PubKey().Bytes()
				} else {
					if hs.remoteStaticPub == nil {
						return errMissingKey("remote static")
					}
				}
				hs.ss.MixHash(keyBytes)
			}
		}
	}
	return nil
}

func (hs *handshakeState) processReadToken(
	token pattern.Token, payload []byte) ([]byte, error) {
	var err error
	switch token {
	case pattern.TokenE:
		payload, err = hs.readTokenE(payload)
		if err != nil {
			return nil, err
		}
	case pattern.TokenS:
		payload, err = hs.readTokenS(payload)
		if err != nil {
			return nil, err
		}
	case pattern.TokenPsk:
		if err := hs.processTokenPsk(); err != nil {
			return nil, err
		}
	default:
		if err := hs.processTokenDH(token); err != nil {
			return nil, err
		}
	}
	return payload, err
}

func (hs *handshakeState) processWriteToken(
	token pattern.Token, payload []byte) error {
	var err error
	switch token {
	case pattern.TokenE:
		if err := hs.writeTokenE(payload); err != nil {
			return err
		}
	case pattern.TokenS:
		if err := hs.writeTokenS(payload); err != nil {
			return err
		}
	case pattern.TokenPsk:
		if err := hs.processTokenPsk(); err != nil {
			return err
		}
	default:
		if err := hs.processTokenDH(token); err != nil {
			return err
		}
	}
	return err
}

func (hs *handshakeState) processTokenPsk() error {
	if len(hs.psks) < hs.pskIndex {
		return errPskIndexOverflow
	}
	token := hs.psks[hs.pskIndex]
	if err := hs.ss.MixKeyAndHash(token[:]); err != nil {
		return err
	}
	hs.pskIndex++
	return nil
}

// readTokenE sets re (which must be empty) to the next DHLEN bytes from the
// payload. Calls MixHash(re.publicKey).
func (hs *handshakeState) readTokenE(payload []byte) ([]byte, error) {
	// check empty
	if hs.remoteEphemeralPub != nil {
		return nil, errKeyNotEmpty("remote ephemeral key")
	}

	// check we have enough bytes to use
	dhlen := hs.ss.curve.Size()
	if len(payload) < dhlen {
		return nil, errInvalidPayload
	}
	hs.remoteEphemeralPub.LoadBytes(payload[:dhlen])
	hs.ss.MixHash(hs.remoteEphemeralPub.Bytes())

	// if psk enabled, call MixKey
	if hs.hp.Modifier.PskMode() {
		hs.ss.MixKey(hs.remoteEphemeralPub.Bytes())
	}

	return payload[dhlen:], nil
}

// writeTokenE sets e (which must be empty) to GENERATE_KEYPAIR(). Appends
// e.public_key to the buffer. Calls MixHash(e.public_key).
func (hs *handshakeState) writeTokenE(payload []byte) error {
	// check empty
	if hs.localEphemeral != nil {
		return errKeyNotEmpty("local ephemeral key")
	}

	key, err := hs.ss.curve.GenerateKeyPair(nil)
	if err != nil {
		return err
	}
	hs.localEphemeral = key
	payload = append(payload, hs.localEphemeral.PubKey().Bytes()...)

	hs.ss.MixHash(hs.localStatic.PubKey().Bytes())

	// if psk enabled, call MixKey
	if hs.hp.Modifier.PskMode() {
		hs.ss.MixKey(hs.remoteEphemeralPub.Bytes())
	}

	return nil
}

// readTokenS sets temp to the next DHLEN + ADLEN bytes of the payload if
// HasKey() == True, or to the next DHLEN bytes otherwise. Sets rs (which must
// be empty) to DecryptAndHash(temp).
func (hs *handshakeState) readTokenS(payload []byte) ([]byte, error) {
	// check empty
	if hs.remoteEphemeralPub != nil {
		return nil, errKeyNotEmpty("remote ephemeral key")
	}

	// The protocol specified a temp key with length DHLEN + 16 bytes, where the
	// 16 is the AD size of the ciphers used. To generalize the usage, we use
	// adlen defined by each cipher so that it's not limited to 16 bytes.
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

// writeTokenS appends EncryptAndHash(s.public_key) to the buffer.
func (hs *handshakeState) writeTokenS(payload []byte) error {
	data, err := hs.ss.EncryptAndHash(hs.localStatic.PubKey().Bytes())
	if err != nil {
		return err
	}
	payload = append(payload, data...)
	return nil
}

// processTokenDH will do a DH exchange on the local and remote key pair.
func (hs *handshakeState) processTokenDH(token pattern.Token) error {
	var local dh.PrivateKey
	var remote dh.PublicKey

	switch token {
	case pattern.TokenEe:
		local = hs.localEphemeral      // e
		remote = hs.remoteEphemeralPub // re
	case pattern.TokenSs:
		local = hs.localStatic      // s
		remote = hs.remoteStaticPub // rs
	case pattern.TokenEs:
		if hs.initiator {
			local = hs.localEphemeral   // e
			remote = hs.remoteStaticPub // rs
		} else {
			local = hs.localStatic         // s
			remote = hs.remoteEphemeralPub // re
		}
	case pattern.TokenSe:
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
