// Package pattern implements the noise handshake pattern.
package pattern

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

var (
	supportedPatterns = make(map[string]*HandshakePattern)

	patternNameRegex = `^[A-Z0-9]+`

	errWrongPreMessage     = errors.New("invalid pattern")
	errInvalidPatternName  = errors.New("invalid handshake pattern name")
	errInvalidModifierName = errors.New("invalid handshake modifier name")
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
	MessagePattern pattern

	// PreMessagePattern stores the tokenized pre-message pattern.
	PreMessagePattern pattern

	// Modifier specifies fallback/psk modifiers.
	Modifier *Modifier
}

func (hp *HandshakePattern) String() string {
	return hp.Name
}

// Modifier implements the two modifiers, psk and fallback specified from the
// noise protocol.
//
// According to the noise specs, a "psk" token is allowed to appear one or more
// times in a handshake pattern, thus a pskIndexes slice is used.
type Modifier struct {
	PskMode      bool
	FallbackMode bool
	pskIndexes   []int
}

// FromString uses the provided name, s, to query a built-in handshake pattern.
func FromString(s string) (*HandshakePattern, error) {
	if supportedPatterns[s] != nil {
		return supportedPatterns[s], nil
	}
	return nil, errUnsupported(s)
}

// Register creates a new handshake pattern with the name and pattern. The
// pattern used must statisfy the requirements specified in the noise protocol
// specification.
func Register(name, pattern string) error {
	modifier, err := parseModifiers(name)
	if err != nil {
		return err
	}

	hp := &HandshakePattern{
		Name:     name,
		Pattern:  pattern,
		Modifier: modifier,
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

func errUnsupported(s string) error {
	return fmt.Errorf("pattern: %s is unsupported", s)
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
	hp.MessagePattern = mp

	// validate modifiers
	if err := hp.validatePsk(); err != nil {
		return err
	}

	if preMessages == "" {
		return nil
	}

	// turn pre-message string into tokens
	pmm, err := tokenize(preMessages, true)
	if err != nil {
		return err
	}
	hp.PreMessagePattern = pmm

	return nil
}

func parseModifiers(s string) (*Modifier, error) {
	re := regexp.MustCompile(patternNameRegex)
	pattern := re.FindString(s)
	if pattern == "" {
		return nil, errInvalidPatternName
	}

	left := strings.Trim(s, pattern)
	if left == "" {
		return nil, nil
	}
	modifiers := strings.Split(left, "+")
	// we only have two modifiers atm, either a fallback or a psk.
	modifier := &Modifier{}
	for _, m := range modifiers {
		if m == "fallback" {
			modifier.FallbackMode = true
		} else {
			// if it's not a fallback, then it must be a psk
			if !strings.HasPrefix(m, "psk") {
				return nil, errInvalidModifierName
			}
			// psk must be in format, psk0, psk1, psk2...
			re := regexp.MustCompile("[0-9]+")
			pskIndex := re.FindString(m)
			if pskIndex == "" {
				return nil, errInvalidModifierName
			}
			modifier.PskMode = true
			index, _ := strconv.Atoi(pskIndex)
			modifier.pskIndexes = append(modifier.pskIndexes, index)
		}
	}
	return modifier, nil
}

func errInvalidPskIndex(i int) error {
	return fmt.Errorf("Invalid psk index: %v", i)
}

func errMissingPskToken(l int) error {
	return fmt.Errorf("Missing psk at line: %v", l)
}

func findAndRemove(s []int, n int) ([]int, bool) {
	for i, item := range s {
		if n == item {
			return append(s[:i], s[i+1:]...), true
		}
	}
	return nil, false
}

// validatePsk checks the psk token is in the right position if enabled.
func (hp *HandshakePattern) validatePsk() error {
	if hp.Modifier == nil {
		return nil
	}
	if !hp.Modifier.PskMode {
		return nil
	}

	// find all psk tokens in the pattern
	var pskIndexes []int
	var found bool
	pskIndexes = hp.Modifier.pskIndexes
	// find psk0
	if hp.MessagePattern[0][1] == TokenPsk {
		pskIndexes, found = findAndRemove(pskIndexes, 0)
		if !found {
			return errInvalidPskIndex(0)
		}
	}

	for i, line := range hp.MessagePattern {
		// find all ending psk tokens
		lastToken := line[len(line)-1]
		if lastToken == TokenPsk {
			pskIndexes, found = findAndRemove(pskIndexes, i+1)
			if !found {
				return errInvalidPskIndex(i + 1)
			}
		}
	}

	if len(pskIndexes) != 0 {
		return errMissingPskToken(pskIndexes[0])
	}

	return nil
}
