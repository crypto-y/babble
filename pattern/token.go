package pattern

import (
	"fmt"
	"strings"
)

type token string

const (
	// token e
	tokenE = token("e")
	// token s
	tokenS = token("s")
	// token ee
	tokenEe = token("ee")
	// token es
	tokenEs = token("es")
	// token se
	tokenSe = token("se")
	// token ss
	tokenSs = token("ss")
	// token psk
	tokenPsk = token("psk")

	// tokenInitiator indicates the message is sent from initiator to responder.
	tokenInitiator = token("->")
	// tokenResponder indicates the message is sent from responder to initiator.
	tokenResponder = token("<-")

	tokenInvalid        = token("invalid")
	preMessageIndicator = "..."

	errConsecutiveTokens = "cannot have two consecutive line using %s"
	errRepeatedTokens    = "token '%s' appeared more than once"
	errMissingToken      = "need token %s before %s"
	errMustBeInitiator   = "the first line must be from initiator"
	errInvalidLine       = "line '%s' is invalid"
	errPskNotAllowed     = "psk is not allowed"
)

type patternLine []token
type pattern []patternLine

func errInvalidPattern(format string, a ...interface{}) error {
	prefix := "Invalid pattern: "
	return fmt.Errorf(prefix+format, a...)
}

// parseMessageLine takes a line of messages, check its validation, and split it
// into a slice of token strings. For example,
// "-> e, s" becomes ["->", "e", "s"]
func parseMessageLine(l string) (patternLine, error) {
	pl := patternLine{}
	tokens := strings.Split(l, " ")

	// a valid line must have at least two items
	if len(tokens) < 2 {
		return nil, errInvalidPattern(errInvalidLine, l)
	}

	// the first item of a line must be a direction, left or right.
	t, err := parseTokenFromString(tokens[0])
	if err != nil {
		return nil, err
	}
	if t != tokenResponder && t != tokenInitiator {
		return nil, errInvalidPattern(errInvalidLine, l)
	}
	pl = append(pl, t)

	for _, token := range tokens[1:] {
		// "e," becomes "e"
		tokenTrimmed := strings.Trim(token, " ,")
		t, err := parseTokenFromString(tokenTrimmed)
		if err != nil {
			return nil, err
		}
		pl = append(pl, t)
	}

	return pl, nil
}

// parseTokenFromString turns a token string into a token type.
func parseTokenFromString(s string) (token, error) {
	switch s {
	case "e":
		return tokenE, nil
	case "s":
		return tokenS, nil
	case "ee":
		return tokenEe, nil
	case "es":
		return tokenEs, nil
	case "se":
		return tokenSe, nil
	case "ss":
		return tokenSs, nil
	case "->":
		return tokenInitiator, nil
	case "<-":
		return tokenResponder, nil
	case "psk":
		return tokenPsk, nil
	default:
		return tokenInvalid, fmt.Errorf("token %s is invalid", s)
	}
}

// tokenize takes a message string and turns it into a pattern. For example, it
// takes,
//   -> e
//   <- e, ee
// and returns, a pattern, which is []patternline. A patternline is []token.
func tokenize(ms string, pre bool) (pattern, error) {
	p := pattern{}

	// remove message whitespaces
	ms = strings.TrimSpace(ms)

	// break the message line by line, a message,
	//   -> e
	//   <- e, ee
	// becomes,
	// "-> e" and "<- e, ee"
	for _, line := range strings.Split(ms, "\n") {
		// remove line whitespaces
		line = strings.TrimSpace(line)

		// "<- e, ee" now becomes, "<-", "e", "ee"
		pl, err := parseMessageLine(line)
		if err != nil {
			return nil, err
		}
		p = append(p, pl)
	}

	// validate pattern
	if err := validatePattern(p, pre); err != nil {
		return nil, err
	}

	return p, nil
}

// validatePattern implements the rules specified in the noise specs, which,
// 1. Parties must not send their static public key or ephemeral public key
// more than once per handshake.
// 2. Parties must not perform a DH calculation more than once per handshake
// (i.e. there must be no more than one occurrence of "ee", "es", "se", or
// "ss" per handshake).
// 3. After an "se" token, the initiator must not send a handshake payload or
// transport payload unless there has also been an "ee" token.
// 4. After an "ss" token, the initiator must not send a handshake payload or
// transport payload unless there has also been an "es" token.
// 5. After an "es" token, the responder must not send a handshake payload or
// transport payload unless there has also been an "ee" token.
// 6. After an "ss" token, the responder must not send a handshake payload or
// transport payload unless there has also been an "se" token.
func validatePattern(pl pattern, pre bool) error {
	tokenSeen := map[token]int{}

	// checks that the first line in the message is an initiator token, with the
	// exception when this is a pre-message pattern.
	isInitiator := pl[0][0] == tokenInitiator
	if !pre && isInitiator != true {
		return errInvalidPattern(errMustBeInitiator)
	}

	prevIsInitiator := !isInitiator
	for _, line := range pl {
		count := map[token]int{}

		isInitiator = line[0] == tokenInitiator
		// In additional to the rules specified in the noise protocol, it's also
		// required that the initiator/responder cannot send two consecutive
		// messages, they must alternate. For instance,
		//   -> e, s
		//   <- e, ee, se
		// is a legal patter, while,
		//   -> e, s
		//   -> e, ee, se
		// is not legal as they are both from the initiator(->)
		if prevIsInitiator == isInitiator {
			return errInvalidPattern(errConsecutiveTokens, line[0])
		}
		prevIsInitiator = isInitiator

		for _, token := range line[1:] {
			// check rule 1 and 2 on each pattern line. Not that a "psk" token
			// is allowed to appear one or more times in a handshake pattern.
			if token != tokenPsk && count[token] > 0 {
				return errInvalidPattern(errRepeatedTokens, token)
			}

			// a psk token is only allowed to appear in pre-message.
			if token == tokenPsk && !pre {
				return errInvalidPattern(errPskNotAllowed)
			}
			count[token]++
			tokenSeen[token]++

			if isInitiator {
				// check rule 3 and 4
				switch token {
				case tokenSe:
					// must have seen an "ee" token before
					if tokenSeen[tokenEe] < 1 {
						return errInvalidPattern(
							errMissingToken, tokenEe, tokenSe)
					}
				case tokenSs:
					// must have seen an "es" token before
					if tokenSeen[tokenEs] < 1 {
						return errInvalidPattern(
							errMissingToken, tokenEs, tokenSs)
					}
				}
			} else {
				// check rule 5 and 6
				switch token {
				case tokenEs:
					// must have seen an "ee" token before
					if tokenSeen[tokenEe] < 1 {
						return errInvalidPattern(
							errMissingToken, tokenEe, tokenEs)
					}
				case tokenSs:
					// must have seen an "se" token before
					if tokenSeen[tokenSe] < 1 {
						return errInvalidPattern(
							errMissingToken, tokenSe, tokenSs)
					}
				}
			}
		}
	}
	return nil
}
