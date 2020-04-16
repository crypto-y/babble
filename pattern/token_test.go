package pattern

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseMessageLine(t *testing.T) {
	testParams := []struct {
		name      string
		message   string
		expected  patternLine
		returnErr bool
	}{
		{"legal line: -> e, s", "-> e, s",
			patternLine{TokenInitiator, TokenE, TokenS}, false},
		{"legal line: <- e, ee, se", "<- e, ee, se",
			patternLine{TokenResponder, TokenE, TokenEe, TokenSe}, false},
		{"illegal line: less than 2 items", "->", nil, true},
		{"illegal line: first item is not a token", "xxx, ->", nil, true},
		{"illegal line: first item is wrong", "e ->", nil, true},
		{"illegal line: contains illegal token", "-> e, xxx, es", nil, true},
	}

	for _, tt := range testParams {
		t.Run(tt.name, func(t *testing.T) {
			pl, err := parseMessageLine(tt.message)
			require.Equal(t, tt.expected, pl, "pattern line not match")
			if tt.returnErr {
				require.NotNil(t, err, "should return an error")
			} else {
				require.Nil(t, err, "should have no error")
			}
		})
	}

}

func TestParseTokenFromString(t *testing.T) {
	testParams := []struct {
		name     string
		expected token
	}{
		{"e", TokenE},
		{"s", TokenS},
		{"ee", TokenEe},
		{"es", TokenEs},
		{"se", TokenSe},
		{"ss", TokenSs},
		{"->", TokenInitiator},
		{"<-", TokenResponder},
		{"psk", TokenPsk},
		{"x", tokenInvalid},
	}

	for _, tt := range testParams {
		t.Run("parse token from string", func(t *testing.T) {
			token, err := parseTokenFromString(tt.name)
			require.Equal(t, tt.expected, token, "token e cannot be parsed")
			if tt.expected == tokenInvalid {
				require.NotNil(t, err, "should return an error")
			} else {
				require.Nil(t, err, "should not return an error")
			}

		})
	}
}

func TestValidatePattern(t *testing.T) {
	testParams := []struct {
		name     string
		p        pattern
		expected error
		isPre    bool
	}{
		{"valid pattern: single line", pattern{
			// -> e
			patternLine{TokenInitiator, TokenE},
		}, nil, false},
		{"valid pattern: two lines", pattern{
			//   -> e
			//   <- e, ee
			patternLine{TokenInitiator, TokenE},
			patternLine{TokenResponder, TokenE, TokenEe},
		}, nil, false},
		{"valid pattern: four lines", pattern{
			//       -> e, es
			//       <- e, ee
			//       -> s
			//       <- se
			patternLine{TokenInitiator, TokenE, TokenEs},
			patternLine{TokenResponder, TokenE, TokenEe},
			patternLine{TokenInitiator, TokenEs},
			patternLine{TokenResponder, TokenSe},
		}, nil, false},
		{"invalid pattern: first token must be initiator", pattern{
			//   <- e
			patternLine{TokenResponder, TokenE},
		}, errInvalidPattern(errMustBeInitiator), false},
		{"invalid pattern: first token can be responder in pre message",
			pattern{
				//   <- e
				patternLine{TokenResponder, TokenE},
			}, nil, true},
		{"invalid pattern: two initiators", pattern{
			//   -> e
			//   -> e, ee
			patternLine{TokenInitiator, TokenE},
			patternLine{TokenInitiator, TokenE, TokenEe},
		}, errInvalidPattern(errConsecutiveTokens, TokenInitiator), false},
		{"invalid pattern: repeated token e", pattern{
			//   -> e, s
			patternLine{TokenInitiator, TokenE, TokenE},
		}, errInvalidPattern(errRepeatedTokens, TokenE), false},
		{"invalid pattern: repeated token es", pattern{
			//   -> es, es
			patternLine{TokenInitiator, TokenEs, TokenEs},
		}, errInvalidPattern(errRepeatedTokens, TokenEs), false},
		{"invalid pattern: token psk is not allowed in message", pattern{
			//   -> psk
			patternLine{TokenInitiator, TokenPsk},
		}, errInvalidPattern(errPskNotAllowed), false},
		{"valid pattern: repeated token psk is allowed in pre", pattern{
			// -> psk, psk
			patternLine{TokenInitiator, TokenPsk, TokenPsk},
		}, nil, true},
		{"invalid pattern: initiator needs ee before se", pattern{
			//   -> se
			patternLine{TokenInitiator, TokenSe},
		}, errInvalidPattern(errMissingToken, TokenEe, TokenSe), false},
		{"invalid pattern: initiator needs es before ss", pattern{
			//   -> ss
			patternLine{TokenInitiator, TokenSs},
		}, errInvalidPattern(errMissingToken, TokenEs, TokenSs), false},
		{"invalid pattern: responder needs ee before es", pattern{
			//   -> e
			//   <- es
			patternLine{TokenInitiator, TokenE},
			patternLine{TokenResponder, TokenEs},
		}, errInvalidPattern(errMissingToken, TokenEe, TokenEs), false},
		{"invalid pattern: responder needs se before ss", pattern{
			//   -> e
			//   <- ss
			patternLine{TokenInitiator, TokenE},
			patternLine{TokenResponder, TokenSs},
		}, errInvalidPattern(errMissingToken, TokenSe, TokenSs), false},
	}

	for _, tt := range testParams {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePattern(tt.p, tt.isPre)
			require.Equal(t, tt.expected, err, "error not match")
		})
	}
}

func TestTokenize(t *testing.T) {
	testParams := []struct {
		name     string
		message  string
		expected pattern
		isPre    bool
		hasErr   bool
	}{
		{"tokenize a normal message", `
			-> e
			<- e, ee`, pattern{
			patternLine{TokenInitiator, TokenE},
			patternLine{TokenResponder, TokenE, TokenEe},
		}, false, false},
		{"tokenize a pre-message", `
			<- s
			-> s`, pattern{
			patternLine{TokenResponder, TokenS},
			patternLine{TokenInitiator, TokenS},
		}, true, false},
		{"wrong line", `
			<-
			-> s`, nil, false, true},
		{"wrong pattern", `
			<- e, e
			-> s`, nil, false, true},
	}

	for _, tt := range testParams {
		t.Run(tt.name, func(t *testing.T) {
			p, err := tokenize(tt.message, tt.isPre)
			if tt.hasErr {
				require.NotNil(t, err, "should have an error returned")
			} else {
				require.Nil(t, err, "should have no error")
			}
			require.Equal(t, tt.expected, p, "pattern not match")
		})
	}
}
