package babble

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/yyforyongyu/babble/dh"
	"github.com/yyforyongyu/babble/pattern"
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

// HandshakeState object contains a symmetricState plus DH variables
// (s, e, rs, re) and a variable representing the handshake pattern. During the
// handshake phase each party has a single HandshakeState, which can be deleted
// once the handshake is finished.
type HandshakeState struct {
	hp *pattern.HandshakePattern
	ss *symmetricState

	// Determines whether the handshake should create the keys automatically.
	autoPadding bool

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

	// SendCipherState is used for encrypting plaintext once the handshake is
	// finished.
	SendCipherState *CipherState

	// RecvCipherState is used for decrypting ciphertext once the handshake is
	// finished.
	RecvCipherState *CipherState

	// psks is slice of 32-byte pre-shared symmetric keys provided by the
	// application. pskIndex tracks the psk token processed.
	psks     [][CipherKeySize]byte
	pskIndex int
}

// Finished returns a bool to indicate whether the handshake is done. The
// patternIndex is used to track the index of last processed pattern, when it
// reaches the end, it indicates the patterns have all been processed.
func (hs *HandshakeState) Finished() bool {
	return hs.patternIndex == len(hs.hp.MessagePattern)
}

// GetChainingKey returns the chaining key in use.
func (hs *HandshakeState) GetChainingKey() []byte {
	return hs.ss.chainingKey[:]
}

// GetDigest returns the hash digest in use.
func (hs *HandshakeState) GetDigest() []byte {
	return hs.ss.GetHandshakeHash()
}

// GetInfo gives a full picture of the handshake internal state.
func (hs *HandshakeState) GetInfo() ([]byte, error) {
	// extract pre-message pattern
	preMsg := map[string]string{}
	for i, l := range hs.hp.PreMessagePattern {
		// TODO: orders may not be preserved
		k := string(strconv.Itoa(i))

		var newLine []string
		for _, t := range l {
			newLine = append(newLine, string(t))
		}
		preMsg[k] = strings.Join(newLine, ", ")
	}

	// extract message pattern
	msg := map[string]string{}
	for i, l := range hs.hp.MessagePattern {
		// TODO: orders may not be preserved
		k := string(strconv.Itoa(i))

		var newLine []string
		for _, t := range l {
			newLine = append(newLine, string(t))
		}
		msg[k] = strings.Join(newLine, ", ")
	}

	type pskMode struct {
		Mode bool              `json:"mode"`
		Keys map[string]string `json:"psks"`
	}

	type pattern struct {
		Psk        pskMode           `json:"psk_mode"`
		Name       string            `json:"name"`
		PreMessage map[string]string `json:"pre_message"`
		Message    map[string]string `json:"message"`
		Index      int               `json:"index"`
	}

	type keyPair struct {
		LocalStaticPriv    string `json:"local_static_priv"`
		LocalStaticPub     string `json:"local_static_pub"`
		LocalEphemeralPriv string `json:"local_ephemeral_priv"`
		LocalEphemeralPub  string `json:"local_ephemeral_pub"`
		RemoteEphemeralPub string `json:"remote_ephemeral_pub"`
		RemoteStaticPub    string `json:"remote_static_pub"`
	}

	type cipher struct {
		Key   string `json:"key"`
		Nonce uint64 `json:"nonce"`
	}

	type rekey struct {
		Interval   uint64 `json:"interval"`
		ResetNonce bool   `json:"reset_nonce"`
	}

	type info struct {
		ChainingKey string  `json:"chaining_key"`
		CipherKey   string  `json:"cipher_key"`
		Digest      string  `json:"digest"`
		Finished    bool    `json:"finished"`
		KeyPair     keyPair `json:"key_pair"`
		Nonce       uint64  `json:"nonce"`
		Pattern     pattern `json:"pattern"`
		SendCipher  cipher  `json:"send_cipher"`
		RecvCipher  cipher  `json:"recv_cipher"`
		Rekey       rekey   `json:"rekey"`
	}

	// extract psk info
	psks := map[string]string{}
	for i, p := range hs.psks {
		psks["psk"+strconv.Itoa(i)] = fmt.Sprintf("%x", p)
	}

	rk := rekey{}
	if hs.ss.cs.RekeyManger != nil {
		rk.Interval = hs.ss.cs.RekeyManger.Interval()
		rk.ResetNonce = hs.ss.cs.RekeyManger.ResetNonce()
	}

	// extract local/remote key pair info
	kp := keyPair{
		LocalStaticPriv:    "",
		LocalStaticPub:     "",
		LocalEphemeralPriv: "",
		LocalEphemeralPub:  "",
		RemoteEphemeralPub: "",
		RemoteStaticPub:    "",
	}
	if hs.localStatic != nil {
		kp.LocalStaticPriv = fmt.Sprintf("%x", hs.localStatic.Bytes())
		kp.LocalStaticPub = fmt.Sprintf("%x",
			hs.localStatic.PubKey().Bytes())
	}
	if hs.localEphemeral != nil {
		kp.LocalEphemeralPriv = fmt.Sprintf("%x", hs.localEphemeral.Bytes())
		kp.LocalEphemeralPub = fmt.Sprintf("%x",
			hs.localEphemeral.PubKey().Bytes())
	}
	if hs.remoteStaticPub != nil {
		kp.RemoteStaticPub = fmt.Sprintf("%x", hs.remoteStaticPub.Bytes())
	}
	if hs.remoteEphemeralPub != nil {
		kp.RemoteEphemeralPub = fmt.Sprintf("%x", hs.remoteEphemeralPub.Bytes())
	}

	i := info{
		ChainingKey: fmt.Sprintf("%x", hs.ss.chainingKey),
		CipherKey:   fmt.Sprintf("%x", hs.ss.cs.key),
		Digest:      fmt.Sprintf("%x", hs.ss.digest),
		Finished:    hs.Finished(),
		KeyPair:     kp,
		Nonce:       hs.ss.cs.nonce,
		Pattern: pattern{
			Name:       hs.hp.Name,
			PreMessage: preMsg,
			Message:    msg,
			Index:      hs.patternIndex - 1,
			Psk: pskMode{
				Mode: hs.pskMode(),
				Keys: psks,
			},
		},
		SendCipher: cipher{
			Key:   fmt.Sprintf("%x", hs.SendCipherState.key),
			Nonce: hs.SendCipherState.nonce,
		},
		RecvCipher: cipher{
			Key:   fmt.Sprintf("%x", hs.RecvCipherState.key),
			Nonce: hs.RecvCipherState.nonce,
		},
		Rekey: rk,
	}

	return jsonMarshal(i)
}

// jsonMarshal encodes the provided interface into a json byte. It won't escape
// unicode "<" or ">", and indents the result using "\t" to beautify it.
func jsonMarshal(t interface{}) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(t); err != nil {
		return nil, err
	}
	// Prettify
	var out bytes.Buffer
	if err := json.Indent(&out, buffer.Bytes(), "", "\t"); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

// initialize takes a valid handshakePattern and an initiator boolean
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
func (hs *HandshakeState) initialize(
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

// ReadMessage takes a byte sequence containing a Noise handshake message, and
// return the decrypted message plaintext.
func (hs *HandshakeState) ReadMessage(message []byte) ([]byte, error) {
	if len(message) > maxMessageSize {
		return nil, errMessageOverflow
	}
	// find the right pattern line
	//
	// first, check the patternIndex is right
	if len(hs.hp.MessagePattern)-1 < hs.patternIndex {
		return nil, errPatternIndexOverflow
	}

	// second, check the direction is right, as ReadMessage should only read
	// remote messages.
	//
	// If the first token is "->", then the message is sent from the initiator
	// to the responder, so it must be read by a responder, otherwise an
	// initiator.
	// if hs.initiator is false, then it's read by a responder.
	// if the first token is TokenInitiator, "->", then it's a message to be
	// read by a responder. Thus it's a valid pattern which should be processed.
	line := hs.hp.MessagePattern[hs.patternIndex]
	if hs.mustWrite(line[0]) {
		return nil, errInvalidDirection("ReadMessage: ", hs.initiator, line[0])
	}

	var err error
	for _, token := range line[1:] {
		message, err = hs.processReadToken(token, message)
		if err != nil {
			return nil, err
		}
	}

	// Now calls DecryptAndHash() on the remaining bytes of the message and
	// stores the output into payloadBuffer.
	plaintext, err := hs.ss.DecryptAndHash(message)
	if err != nil {
		return nil, err
	}

	// when finished, increment the pattern index for next round
	if err := hs.incrementPatternIndexAndSplit(); err != nil {
		return nil, err
	}

	return plaintext, nil
}

// WriteMessage takes a payload byte sequence which may be zero-length, and
// returns the ciphertext.
func (hs *HandshakeState) WriteMessage(payload []byte) ([]byte, error) {
	if len(payload) > maxMessageSize {
		return nil, errMessageOverflow
	}

	// find the right pattern line
	//
	// first, check the patternIndex is right
	if len(hs.hp.MessagePattern)-1 < hs.patternIndex {
		return nil, errPatternIndexOverflow
	}

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
	line := hs.hp.MessagePattern[hs.patternIndex]
	if !hs.mustWrite(line[0]) {
		return nil, errInvalidDirection("WriteMessage: ", hs.initiator, line[0])
	}

	var err error
	var buffer []byte
	for _, token := range line[1:] {
		buffer, err = hs.processWriteToken(token, buffer)
		if err != nil {
			return nil, err
		}
	}

	// Appends EncryptAndHash(payload) to the buffer.
	ciphertext, err := hs.ss.EncryptAndHash(payload)
	if err != nil {
		return nil, err
	}
	buffer = append(buffer, ciphertext...)

	// when finished, increment the pattern index for next round
	if err := hs.incrementPatternIndexAndSplit(); err != nil {
		return nil, err
	}

	return buffer, nil
}

// reset sets every thing to nil value.
func (hs *HandshakeState) reset() {
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

	if hs.SendCipherState != nil {
		hs.SendCipherState.reset()
		hs.SendCipherState = nil
	}

	if hs.RecvCipherState != nil {
		hs.RecvCipherState.reset()
		hs.RecvCipherState = nil
	}
}

func errInvalidDHToken(t pattern.Token) error {
	return fmt.Errorf("invalid token during DHKE: %s", t)
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
	return fmt.Errorf("missing key: %s", s)
}

// handleMissingKeyE will create the missing ephemeral key if the autoPadding
// flag is turned on.
func (hs *HandshakeState) handleMissingKeyE() error {
	if hs.autoPadding {
		key, err := hs.ss.curve.GenerateKeyPair(nil)
		if err != nil {
			return err
		}
		hs.localEphemeral = key
	} else {
		return errMissingKey("local ephemeral key")
	}
	return nil
}

// handleMissingKeyS will create the missing static key if the autoPadding flag
// is turned on.
func (hs *HandshakeState) handleMissingKeyS() error {
	if hs.autoPadding {
		key, err := hs.ss.curve.GenerateKeyPair(nil)
		if err != nil {
			return err
		}
		hs.localStatic = key
	} else {
		return errMissingKey("local static key")
	}
	return nil
}

func (hs *HandshakeState) incrementPatternIndexAndSplit() error {
	hs.patternIndex++
	if hs.patternIndex > len(hs.hp.MessagePattern) {
		return errPatternIndexOverflow
	}
	if !hs.Finished() {
		return nil
	}

	// when finished, returns two new CipherState objects by calling Split().
	c1, c2, err := hs.ss.Split()
	if err != nil {
		return err
	}
	if hs.initiator {
		hs.SendCipherState = c1
		hs.RecvCipherState = c2
	} else {
		hs.SendCipherState = c2
		hs.RecvCipherState = c1
	}
	return nil
}

// mustWrite checks whether a read/write function should be called. If a message
// pattern starts with "->", and the caller is an initiator, then it's must
// perform write, otherwise it must perform read. This is useful when deciding
// whether a local or remote ephemeral/static key should be used. For instance,
// when processing a pattern line, "-> s",
//  - if the caller is an initiator, then the local static key should be used
//    for writting;
//  - if the caller is an responder, then the remote static key should be used
//    for reading.
// when performing reading/writing on this pattern,
//  - if the caller is an initiator, it is not allowed to read this line;
//  - if the caller is an responder, it is not allowed to write this line.
func (hs *HandshakeState) mustWrite(t pattern.Token) bool {
	return hs.initiator == (t == pattern.TokenInitiator)
}

func newHandshakeState(protocolName, prologue []byte, psks [][]byte,
	initiator bool,
	ss *symmetricState, hp *pattern.HandshakePattern,
	s, e dh.PrivateKey, rs, re dh.PublicKey,
	autoPadding bool) (*HandshakeState, error) {
	// Protocol name must be 255 bytes or less
	if len(protocolName) > 255 {
		return nil, errProtocolNameInvalid
	}

	// must provide symmetric state
	if ss == nil {
		return nil, errMissingSymmetricState
	}
	hs := &HandshakeState{ss: ss, autoPadding: autoPadding}

	// must provide handshake pattern
	if hp == nil {
		return nil, errMissingHandshakePattern
	}

	// call built-in initialize
	if err := hs.initialize(
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

	// finally, validate that necessary keys are provided for the pattern.
	if err := hs.validateKeys(); err != nil {
		return nil, err
	}

	return hs, nil
}

// processPreMessage calls MixHash() once for each public key listed in the
// pre-messages from handshakePattern, with the specified public key as input.
//
// If both initiator and responder have pre-messages, the initiator's public
// keys are hashed first. If multiple public keys are listed in either party's
// pre-message, the public keys are hashed in the order that they are listed.
func (hs *HandshakeState) processPreMessage() error {
	// PreMessagePattern is a paragraph in format,
	// -> s
	// <- s
	for _, line := range hs.hp.PreMessagePattern {
		// pattern is a line in format,
		// -> s
		for _, token := range line {

			direction := line[0]

			switch token {
			case pattern.TokenE:
				if err := hs.processPreTokenE(direction); err != nil {
					return err
				}
			case pattern.TokenS:
				if err := hs.processPreTokenS(direction); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (hs *HandshakeState) processPreTokenE(d pattern.Token) error {
	var keyBytes []byte
	// find out whether a local or remote key to be used
	if hs.mustWrite(d) {
		if hs.localEphemeral == nil {
			if err := hs.handleMissingKeyE(); err != nil {
				return err
			}
		}
		keyBytes = hs.localEphemeral.PubKey().Bytes()
	} else {
		if hs.remoteEphemeralPub == nil {
			return errMissingKey("remote ephemeral key")
		}
		keyBytes = hs.remoteEphemeralPub.Bytes()
	}

	hs.ss.MixHash(keyBytes)
	// if psk enabled, call MixKey
	if hs.pskMode() {
		hs.ss.MixKey(keyBytes)
	}
	return nil
}

func (hs *HandshakeState) processPreTokenS(d pattern.Token) error {
	var keyBytes []byte
	// find out whether a local or remote key to be used
	if hs.mustWrite(d) {
		if hs.localStatic == nil {
			if err := hs.handleMissingKeyS(); err != nil {
				return err
			}
		}
		keyBytes = hs.localStatic.PubKey().Bytes()
	} else {
		if hs.remoteStaticPub == nil {
			return errMissingKey("remote static key")
		}
		keyBytes = hs.remoteStaticPub.Bytes()
	}

	hs.ss.MixHash(keyBytes)
	return nil
}

func (hs *HandshakeState) processReadToken(
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

func (hs *HandshakeState) processWriteToken(
	token pattern.Token, payload []byte) ([]byte, error) {
	var err error
	switch token {
	case pattern.TokenE:
		payload, err = hs.writeTokenE(payload)
		if err != nil {
			return nil, err
		}
	case pattern.TokenS:
		payload, err = hs.writeTokenS(payload)
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

	return payload, nil
}

func (hs *HandshakeState) processTokenPsk() error {
	if len(hs.psks)-1 < hs.pskIndex {
		return errPskIndexOverflow
	}
	token := hs.psks[hs.pskIndex]
	// safe to ignore the error here
	if err := hs.ss.MixKeyAndHash(token[:]); err != nil {
		return err
	}
	hs.pskIndex++

	return nil
}

func (hs *HandshakeState) pskMode() bool {
	return hs.hp.Modifier != nil && hs.hp.Modifier.PskMode()
}

// validateKeys validate the four keys supplied during creation of the handshake
// state.
func (hs *HandshakeState) validateKeys() error {
	for _, line := range hs.hp.MessagePattern {
		for _, token := range line[1:] {
			switch token {
			case pattern.TokenE:
				if hs.mustWrite(line[0]) {
					// e must be empty for writing
					if hs.localEphemeral != nil {
						return errKeyNotEmpty("local ephemeral key")
					}
				} else {
					// re must be empty for reading
					if hs.remoteEphemeralPub != nil {
						return errKeyNotEmpty("remote ephemeral key")
					}
				}
			case pattern.TokenS:
				if hs.mustWrite(line[0]) {
					// s must NOT be empty for writing
					if hs.localStatic == nil {
						if err := hs.handleMissingKeyS(); err != nil {
							return err
						}
					}
				} else {
					// rs must be empty for reading
					if hs.remoteStaticPub != nil {
						return errKeyNotEmpty("remote static key")
					}
				}
			}
		}
	}

	return nil
}

// readTokenE sets re (which must be empty) to the next DHLEN bytes from the
// payload. Calls MixHash(re.publicKey).
func (hs *HandshakeState) readTokenE(payload []byte) ([]byte, error) {
	// check empty
	if hs.remoteEphemeralPub != nil {
		return nil, errKeyNotEmpty("remote ephemeral key")
	}

	// check we have enough bytes to use
	dhlen := hs.ss.curve.Size()
	if len(payload) < dhlen {
		return nil, errInvalidPayload
	}

	pub, err := hs.ss.curve.LoadPublicKey(payload[:dhlen])
	if err != nil {
		return nil, err
	}
	hs.remoteEphemeralPub = pub
	hs.ss.MixHash(hs.remoteEphemeralPub.Bytes())

	// if psk enabled, call MixKey
	if hs.pskMode() {
		hs.ss.MixKey(hs.remoteEphemeralPub.Bytes())
	}

	return payload[dhlen:], nil
}

// writeTokenE sets e (which must be empty) to GENERATE_KEYPAIR(). Appends
// e.public_key to the buffer. Calls MixHash(e.public_key).
func (hs *HandshakeState) writeTokenE(payload []byte) ([]byte, error) {
	// check empty
	if hs.localEphemeral != nil {
		return nil, errKeyNotEmpty("local ephemeral key")
	}

	key, err := hs.ss.curve.GenerateKeyPair(nil)
	if err != nil {
		return nil, err
	}
	hs.localEphemeral = key
	payload = append(payload, hs.localEphemeral.PubKey().Bytes()...)

	hs.ss.MixHash(hs.localEphemeral.PubKey().Bytes())

	// if psk enabled, call MixKey
	if hs.pskMode() {
		hs.ss.MixKey(hs.localEphemeral.PubKey().Bytes())
	}

	return payload, nil
}

// readTokenS sets temp to the next DHLEN + ADLEN bytes of the payload if
// HasKey() == True, or to the next DHLEN bytes otherwise. Sets rs (which must
// be empty) to DecryptAndHash(temp).
func (hs *HandshakeState) readTokenS(payload []byte) ([]byte, error) {
	// check empty
	if hs.remoteStaticPub != nil {
		return nil, errKeyNotEmpty("remote static key")
	}

	// The protocol specified a temp key with length DHLEN + 16 bytes, where the
	// 16 is the AD size of the ciphers used. To generalize the usage, we use
	// adlen defined by each cipher so that it's not limited to 16 bytes.
	dhlen := hs.ss.curve.Size()
	adlen := hs.ss.cs.cipher.Cipher().Overhead()

	tempLen := dhlen
	if hs.ss.cs.hasKey() {
		tempLen = dhlen + adlen
	}

	// check we have enough bytes to use
	if len(payload) < tempLen {
		return nil, errInvalidPayload
	}

	temp := make([]byte, tempLen)
	copy(temp[:], payload[:tempLen])
	data, err := hs.ss.DecryptAndHash(temp)
	if err != nil {
		return nil, err
	}

	// create the public key
	pub, err := hs.ss.curve.LoadPublicKey(data)
	if err != nil {
		return nil, err
	}
	hs.remoteStaticPub = pub

	return payload[tempLen:], nil

}

// writeTokenS appends EncryptAndHash(s.public_key) to the buffer.
func (hs *HandshakeState) writeTokenS(payload []byte) ([]byte, error) {
	// local static must not be empty, it should be supplied via creation of
	// the handshake state.
	if hs.localStatic == nil {
		return nil, errMissingKey("local static key")
	}
	data, err := hs.ss.EncryptAndHash(hs.localStatic.PubKey().Bytes())
	if err != nil {
		return nil, err
	}
	payload = append(payload, data...)

	return payload, nil
}

// processTokenDH will do a DH exchange on the local and remote key pair.
func (hs *HandshakeState) processTokenDH(token pattern.Token) error {
	var local dh.PrivateKey
	var remote dh.PublicKey

	switch token {
	case pattern.TokenEe:
		// if it's "ee", the first is the local ephemeral key, the second is the
		// remote ephemeral key.
		local = hs.localEphemeral      // e
		remote = hs.remoteEphemeralPub // re

	case pattern.TokenSs:
		// if it's "ss", the first key is the local static key, the second is
		// the remote static key.
		local = hs.localStatic      // s
		remote = hs.remoteStaticPub // rs

	case pattern.TokenEs:
		if hs.initiator {
			// if it's "es", when it's an initiator, the first token is it's
			// local ephemeral key, the second is the remote static key.
			local = hs.localEphemeral   // e
			remote = hs.remoteStaticPub // rs
		} else {
			// when it's a responder, the first "e" is the remote ephemeral key,
			// the second "s" is the local static key.
			local = hs.localStatic         // s
			remote = hs.remoteEphemeralPub // re
		}
	case pattern.TokenSe:
		if hs.initiator {
			// if it's "se", when it's an initiator, the first is its local
			// static key, the second is the remote ephemeral key.
			local = hs.localStatic         // s
			remote = hs.remoteEphemeralPub // re
		} else {
			// when it's a responder, the first "s" is the remote static key,
			// the second "e" is the local ephemeral key.
			local = hs.localEphemeral   // e
			remote = hs.remoteStaticPub // rs
		}
	default:
		return errInvalidDHToken(token)
	}

	if local == nil || remote == nil {
		return errMissingKey("missing key when performing DH")
	}

	digest, err := local.DH(remote.Bytes())
	if err != nil {
		return err
	}
	hs.ss.MixKey(digest)

	return nil
}
