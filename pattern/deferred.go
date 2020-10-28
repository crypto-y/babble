package pattern

// An additional set of handshake patterns can be described which defer these
// authentication DHs to the next message. To name these deferred handshake
// patterns, the numeral "1" is used after the first and/or second character
// in a fundamental pattern name to indicate that the initiator and/or
// responder's authentication DH is deferred to the next message.
var (
	deferred = []struct {
		name    string
		pattern string
	}{
		{
			name: "NK1",
			pattern: `
				<- s
				...
				-> e
				<- e, ee, es`,
		}, {
			name: "NX1",
			pattern: `
				-> e
				<- e, ee, s
				-> es`,
		}, {
			name: "X1N",
			pattern: `
				-> e
				<- e, ee
				-> s
				<- se`,
		}, {
			name: "X1K",
			pattern: `
				<- s
				...
				-> e, es
				<- e, ee
				-> s
				<- se`,
		}, {
			name: "XK1",
			pattern: `
				<- s
				...
				-> e
				<- e, ee, es
				-> s, se`,
		}, {
			name: "X1K1",
			pattern: `
				<- s
				...
				-> e
				<- e, ee, es
				-> s
				<- se`,
		}, {
			name: "X1X",
			pattern: `
				-> e
				<- e, ee, s, es
				-> s
				<- se`,
		}, {
			name: "XX1",
			pattern: `
				-> e
				<- e, ee, s
				-> es, s, se`,
		}, {
			name: "X1X1",
			pattern: `
				-> e
				<- e, ee, s
				-> es, s
				<- se`,
		}, {
			name: "K1N",
			pattern: `
				-> s
				...
				-> e
				<- e, ee
				-> se`,
		}, {
			name: "K1K",
			pattern: `
				-> s
				<- s
				...
				-> e, es
				<- e, ee
				-> se`,
		}, {
			name: "KK1",
			pattern: `
				-> s
				<- s
				...
				-> e
				<- e, ee, se, es`,
		}, {
			name: "K1K1",
			pattern: `
				-> s
				<- s
				...
				-> e
				<- e, ee, es
				-> se`,
		}, {
			name: "K1X",
			pattern: `
				-> s
				...
				-> e
				<- e, ee, s, es
				-> se`,
		}, {
			name: "KX1",
			pattern: `
				-> s
				...
				-> e
				<- e, ee, se, s
				-> es`,
		}, {
			name: "K1X1",
			pattern: `
				-> s
				...
				-> e
				<- e, ee, s
				-> se, es`,
		}, {
			name: "I1N",
			pattern: `
				-> e, s
				<- e, ee
				-> se`,
		}, {
			name: "I1K",
			pattern: `
				<- s
				...
				-> e, es, s
				<- e, ee
				-> se`,
		}, {
			name: "IK1",
			pattern: `
				<- s
				...
				-> e, s
				<- e, ee, se, es`,
		}, {
			name: "I1K1",
			pattern: `
				<- s
				...
				-> e, s
				<- e, ee, es
				-> se`,
		}, {
			name: "I1X",
			pattern: `
				-> e, s
				<- e, ee, s, es
				-> se`,
		}, {
			name: "IX1",
			pattern: `
				-> e, s
				<- e, ee, se, s
				-> es`,
		}, {
			name: "I1X1",
			pattern: `
				-> e, s
				<- e, ee, s
				-> se, es`,
		},
	}
)

func init() {
	for _, p := range deferred {
		if err := Register(p.name, p.pattern); err != nil {
			panic(err)
		}
	}
}
