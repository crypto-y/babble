package pattern

// One-way handshake patterns are named with a single character, which indicates
// the status of the sender's static key.
//   N = No static key for sender
//   K = Static key for sender Known to recipient
//   X = Static key for sender Xmitted ("transmitted") to recipient
var (
	oneWay = []struct {
		name    string
		pattern string
	}{
		{
			name: "N",
			pattern: `
				<- s
				...
				-> e, es`,
		}, {
			name: "K",
			pattern: `
				-> s
				<- s
				...
				-> e, es, ss`,
		}, {
			name: "X",
			pattern: `
				<- s
				...
				-> e, es, s, ss`,
		},
	}
)

func init() {
	for _, p := range oneWay {
		Register(p.name, p.pattern)
	}
}
