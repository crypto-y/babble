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
// times in a handshake pattern, thus a PskIndexes slice is used.
type Modifier struct {
	Fallback   bool
	PskIndexes []int
}

// PskMode specifies whether there is a psk modifier.
func (m *Modifier) PskMode() bool {
	return len(m.PskIndexes) != 0
}

// FromString uses the provided name, s, to query a built-in handshake pattern.
func FromString(s string) (*HandshakePattern, error) {
	// First, we query using the fullname s
	if supportedPatterns[s] != nil {
		return supportedPatterns[s], nil
	}

	// Second, if fullname is not found, then we parse out the pattern name,
	// XXpsk0+fallback becomes XX and psk0+fallback, and query the XX.
	re := regexp.MustCompile(patternNameRegex)
	name := re.FindString(s)
	if name == "" {
		return nil, errInvalidPatternName
	}
	// query the name
	hp := supportedPatterns[name]
	if hp == nil {
		return nil, errUnsupported(s)
	}

	// make a copy
	newHp := &HandshakePattern{
		Name:              s,
		Pattern:           hp.Pattern,
		PreMessagePattern: hp.PreMessagePattern,
	}
	// deep copy the patterns
	p := pattern{}
	for _, pl := range hp.MessagePattern {
		newPl := patternLine{}
		for _, l := range pl {
			newPl = append(newPl, l)
		}
		p = append(p, newPl)
	}
	newHp.MessagePattern = p

	// mount the modifiers if specified, eg, psk and fallback
	modifier := strings.Trim(s, name)
	if err := newHp.mountModifiers(modifier); err != nil {
		return nil, err
	}

	// pad the psk tokens
	newHp.padPskToken()

	// cache it for future reference
	supportedPatterns[s] = newHp

	return newHp, nil
}

// Register creates a new handshake pattern with the name and pattern. The
// pattern used must statisfy the requirements specified in the noise protocol
// specification.
func Register(s, pattern string) error {
	// parse out the pattern name, XXpsk0+fallback becomes XX and psk0+fallback
	re := regexp.MustCompile(patternNameRegex)
	name := re.FindString(s)
	if name == "" {
		return errInvalidPatternName
	}

	hp := &HandshakePattern{
		Name:    s,
		Pattern: pattern,
	}
	// mount the modifiers if specified, eg, psk and fallback
	modifier := strings.Trim(s, name)
	if err := hp.mountModifiers(modifier); err != nil {
		return err
	}

	// validate the pattern
	if err := hp.loadPattern(); err != nil {
		return err
	}

	supportedPatterns[s] = hp
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

func (hp *HandshakePattern) mountModifiers(s string) error {
	if s == "" {
		return nil
	}

	modifiers := strings.Split(s, "+")
	// we only have two modifiers atm, either a fallback or a psk.
	modifier := &Modifier{}
	for _, m := range modifiers {
		if m == "fallback" {
			modifier.Fallback = true
		} else {
			// if it's not a fallback, then it must be a psk
			if !strings.HasPrefix(m, "psk") {
				return errInvalidModifierName
			}
			// psk must be in format, psk0, psk1, psk2...
			re := regexp.MustCompile("[0-9]+")
			pskIndex := re.FindString(m)
			if pskIndex == "" {
				return errInvalidModifierName
			}
			index, _ := strconv.Atoi(pskIndex)
			modifier.PskIndexes = append(modifier.PskIndexes, index)
		}
	}

	hp.Modifier = modifier
	return nil
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

// padPskToken will pad the psk tokens if they are missing in the pattern but
// specified in the modifiers.
func (hp *HandshakePattern) padPskToken() {
	if hp.Modifier == nil || !hp.Modifier.PskMode() {
		return
	}

	// now we will pad all the psk tokens
	for _, i := range hp.Modifier.PskIndexes {
		if i == 0 {
			hp.MessagePattern[0] = append(
				hp.MessagePattern[0][:1], append(
					patternLine{TokenPsk}, hp.MessagePattern[0][1:]...)...,
			)
		} else {
			hp.MessagePattern[i-1] = append(hp.MessagePattern[i-1], TokenPsk)
		}
	}

}

// validatePsk checks the psk token is in the right position if enabled.
func (hp *HandshakePattern) validatePsk() error {
	if hp.Modifier == nil {
		return nil
	}
	if !hp.Modifier.PskMode() {
		return nil
	}

	// find all psk tokens in the pattern
	var PskIndexes []int
	var found bool
	PskIndexes = hp.Modifier.PskIndexes
	// find psk0
	if hp.MessagePattern[0][1] == TokenPsk {
		PskIndexes, found = findAndRemove(PskIndexes, 0)
		if !found {
			return errInvalidPskIndex(0)
		}
	}

	for i, line := range hp.MessagePattern {
		// find all ending psk tokens
		lastToken := line[len(line)-1]
		if lastToken == TokenPsk {
			PskIndexes, found = findAndRemove(PskIndexes, i+1)
			if !found {
				return errInvalidPskIndex(i + 1)
			}
		}
	}

	if len(PskIndexes) != 0 {
		return errMissingPskToken(PskIndexes[0])
	}

	return nil
}
