package pattern

// Interactive handshake patterns
// The first character refers to the initiator's static key:
//   N = No static key for initiator
//   K = Static key for initiator Known to responder
//   X = Static key for initiator Xmitted ("transmitted") to responder
//   I = Static key for initiator Immediately transmitted to responder, despite
//       reduced or absent identity hiding.
// The second character refers to the responder's static key:
//   N = No static key for responder
//   K = Static key for responder Known to initiator
//   X = Static key for responder Xmitted ("transmitted") to initiator
var (
	interactive = []struct {
		name    string
		pattern string
	}{
		{
			name: "NN",
			pattern: `
  				-> e
  				<- e, ee`,
		}, {
			name: "KN",
			pattern: `
  				-> s
  				...
  				-> e
  				<- e, ee, se`,
		}, {
			name: "NK",
			pattern: `
  				<- s
  				...
  				-> e, es
  				<- e, ee`,
		}, {
			name: "KK",
			pattern: `
  				-> s
  				<- s
  				...
  				-> e, es, ss
  				<- e, ee, se`,
		}, {
			name: "NX",
			pattern: `
  				-> e
  				<- e, ee, s, es`,
		}, {
			name: "KX",
			pattern: `
  				-> s
  				...
  				-> e
  				<- e, ee, se, s, es`,
		}, {
			name: "XN",
			pattern: `
  				-> e
  				<- e, ee
  				-> s, se`,
		}, {
			name: "IN",
			pattern: `
  				-> e, s
  				<- e, ee, se`,
		}, {
			name: "XK",
			pattern: `
  				<- s
  				...
  				-> e, es
  				<- e, ee
  				-> s, se`,
		}, {
			name: "IK",
			pattern: `
  				<- s
  				...
  				-> e, es, s, ss
  				<- e, ee, se`,
		}, {
			name: "XX",
			pattern: `
  				-> e
  				<- e, ee, s, es
  				-> s, se`,
		}, {
			name: "IX",
			pattern: `
  				-> e, s
  				<- e, ee, se, s, es`,
		},
	}
)

func init() {
	for _, p := range interactive {
		if err := Register(p.name, p.pattern); err != nil {
			panic(err)
		}
	}
}
