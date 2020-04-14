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
			patternLine{tokenInitiator, tokenE, tokenS}, false},
		{"legal line: <- e, ee, se", "<- e, ee, se",
			patternLine{tokenResponder, tokenE, tokenEe, tokenSe}, false},
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
		{"e", tokenE},
		{"s", tokenS},
		{"ee", tokenEe},
		{"es", tokenEs},
		{"se", tokenSe},
		{"ss", tokenSs},
		{"->", tokenInitiator},
		{"<-", tokenResponder},
		{"psk", tokenPsk},
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
			patternLine{tokenInitiator, tokenE},
		}, nil, false},
		{"valid pattern: two lines", pattern{
			//   -> e
			//   <- e, ee
			patternLine{tokenInitiator, tokenE},
			patternLine{tokenResponder, tokenE, tokenEe},
		}, nil, false},
		{"valid pattern: four lines", pattern{
			//       -> e, es
			//       <- e, ee
			//       -> s
			//       <- se
			patternLine{tokenInitiator, tokenE, tokenEs},
			patternLine{tokenResponder, tokenE, tokenEe},
			patternLine{tokenInitiator, tokenEs},
			patternLine{tokenResponder, tokenSe},
		}, nil, false},
		{"invalid pattern: first token must be initiator", pattern{
			//   <- e
			patternLine{tokenResponder, tokenE},
		}, errInvalidPattern(errMustBeInitiator), false},
		{"invalid pattern: first token can be responder in pre message",
			pattern{
				//   <- e
				patternLine{tokenResponder, tokenE},
			}, nil, true},
		{"invalid pattern: two initiators", pattern{
			//   -> e
			//   -> e, ee
			patternLine{tokenInitiator, tokenE},
			patternLine{tokenInitiator, tokenE, tokenEe},
		}, errInvalidPattern(errConsecutiveTokens, tokenInitiator), false},
		{"invalid pattern: repeated token e", pattern{
			//   -> e, s
			patternLine{tokenInitiator, tokenE, tokenE},
		}, errInvalidPattern(errRepeatedTokens, tokenE), false},
		{"invalid pattern: repeated token es", pattern{
			//   -> es, es
			patternLine{tokenInitiator, tokenEs, tokenEs},
		}, errInvalidPattern(errRepeatedTokens, tokenEs), false},
		{"invalid pattern: token psk is not allowed in message", pattern{
			//   -> psk
			patternLine{tokenInitiator, tokenPsk},
		}, errInvalidPattern(errPskNotAllowed), false},
		{"valid pattern: repeated token psk is allowed in pre", pattern{
			// -> psk, psk
			patternLine{tokenInitiator, tokenPsk, tokenPsk},
		}, nil, true},
		{"invalid pattern: initiator needs ee before se", pattern{
			//   -> se
			patternLine{tokenInitiator, tokenSe},
		}, errInvalidPattern(errMissingToken, tokenEe, tokenSe), false},
		{"invalid pattern: initiator needs es before ss", pattern{
			//   -> ss
			patternLine{tokenInitiator, tokenSs},
		}, errInvalidPattern(errMissingToken, tokenEs, tokenSs), false},
		{"invalid pattern: responder needs ee before es", pattern{
			//   -> e
			//   <- es
			patternLine{tokenInitiator, tokenE},
			patternLine{tokenResponder, tokenEs},
		}, errInvalidPattern(errMissingToken, tokenEe, tokenEs), false},
		{"invalid pattern: responder needs se before ss", pattern{
			//   -> e
			//   <- ss
			patternLine{tokenInitiator, tokenE},
			patternLine{tokenResponder, tokenSs},
		}, errInvalidPattern(errMissingToken, tokenSe, tokenSs), false},
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
			patternLine{tokenInitiator, tokenE},
			patternLine{tokenResponder, tokenE, tokenEe},
		}, false, false},
		{"tokenize a pre-message", `
			<- s
			-> s`, pattern{
			patternLine{tokenResponder, tokenS},
			patternLine{tokenInitiator, tokenS},
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
