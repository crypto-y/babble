// Package vectors is created to help the vector test.
// Credit: https://github.com/Yawning/nyquist/tree/master/vectors
package vectors

import "encoding/hex"

// HexBuffer is a byte slice that will marshal to/unmarshal from a hex encoded
// string.
type HexBuffer []byte

// MarshalText implements the TextMarshaler interface.
func (x *HexBuffer) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(*x)), nil
}

// UnmarshalText implements the TextUnmarshaler interface.
func (x *HexBuffer) UnmarshalText(data []byte) error {
	b, err := hex.DecodeString(string(data))
	if err != nil {
		return err
	}

	if len(b) == 0 {
		*x = nil
	} else {
		*x = b
	}

	return nil
}

// Message is a test vector handshake message.
type Message struct {
	Payload    HexBuffer `json:"payload"`
	Ciphertext HexBuffer `json:"ciphertext"`
}

// Vector is a single test vector case.
type Vector struct {
	Name string `json:"name"`

	ProtocolName    string `json:"protocol_name"`
	Fail            bool   `json:"fail"`
	Fallback        bool   `json:"fallback"`
	FallbackPattern string `json:"fallback_pattern"`

	InitPrologue     HexBuffer   `json:"init_prologue"`
	InitPsks         []HexBuffer `json:"init_psks"`
	InitStatic       HexBuffer   `json:"init_static"`
	InitEphemeral    HexBuffer   `json:"init_ephemeral"`
	InitRemoteStatic HexBuffer   `json:"init_remote_static"`

	RespPrologue     HexBuffer   `json:"resp_prologue"`
	RespPsks         []HexBuffer `json:"resp_psks"`
	RespStatic       HexBuffer   `json:"resp_static"`
	RespEphemeral    HexBuffer   `json:"resp_ephemeral"`
	RespRemoteStatic HexBuffer   `json:"resp_remote_static"`

	HandshakeHash HexBuffer `json:"handshake_hash"`

	Messages []Message `json:"messages"`
}

// File is a collection of test vectors.
type File struct {
	Vectors []Vector `json:"vectors"`
}
