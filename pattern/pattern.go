// Package pattern implements the noise handshake pattern.
package pattern

import (
	"strings"

	"github.com/pkg/errors"
)

var (
	errWrongPreMessage = errors.New("invalid pattern")
	supportedPatterns  = make(map[string]*HandshakePattern)
)

// HandshakePattern represents a noise handshake pattern. It has a strict
// definition which can be found following the link:
//   https://noiseprotocol.org/noise.html#handshake-patterns
type HandshakePattern struct {
	// Name is made of two parts:
	//  - the pattern name, must be an uppercase ASCII string containing only
	// 	  alphabetic characters or numerals.
	//  - the pattern modifier name, must be a lowercase alphanumeric ASCII
	//    string that begins with an alphabetic character.
	Name string

	// Pattern is a piece of string, for instance,
	// p := `
	//   -> s
	//   <- s
	//   ...
	//   -> e, es, ss
	//   <- e, ee, se`
	Pattern string

	// MessagePattern stores the tokenized message pattern.
	MessagePattern *pattern

	// PreMessagePattern stores the tokenized pre-message pattern.
	PreMessagePattern *pattern
}

// loadPattern takes a handskake pattern string, and turns it into a
// pre-message(if any) and a message pattern.
func (hp *HandshakePattern) loadPattern() error {
	// first, check there is only one "..."
	patterns := strings.Split(hp.Pattern, "...")
	if len(patterns) > 2 {
		return errWrongPreMessage
	}

	var preMessages string
	var messages string

	// parse out pre-message if needed
	if len(patterns) > 1 {
		preMessages = patterns[0]
		messages = patterns[1]
	} else {
		messages = patterns[0]
	}

	// turn message string into tokens
	mp, err := tokenize(messages, false)
	if err != nil {
		return err
	}
	hp.MessagePattern = &mp

	if preMessages == "" {
		return nil
	}

	// turn pre-message string into tokens
	pmm, err := tokenize(preMessages, true)
	if err != nil {
		return err
	}
	hp.PreMessagePattern = &pmm

	return nil
}

// FromString uses the provided name, s, to query a built-in handshake pattern.
func FromString(s string) *HandshakePattern {
	return supportedPatterns[s]
}

// Register creates a new handshake pattern with the name and pattern. The
// pattern used must statisfy the requirements specified in the noise protocol
// specification.
func Register(name, pattern string) error {
	// TODO: validate name
	hp := &HandshakePattern{
		Name:    name,
		Pattern: pattern,
	}
	if err := hp.loadPattern(); err != nil {
		return err
	}
	supportedPatterns[name] = hp
	return nil
}

// SupportedPatterns gives the names of all the patterns registered. If no new
// patterns are registered, it returns a total of 38 patterns, orders not
// preserved.
func SupportedPatterns() string {
	keys := make([]string, 0, len(supportedPatterns))
	for k := range supportedPatterns {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}
