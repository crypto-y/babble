# Noise Handshake Patterns

This package implements the handshake patterns specified in the [noise protocol](https://noiseprotocol.org/noise.html#handshake-patterns).

### Built-in Patterns

There are a total of 38 patterns built, in which,

**[One-way handshake patterns](https://noiseprotocol.org/noise.html#one-way-handshake-patterns)**

3 one-way handskake patterns.

**[Interactive handshake patterns](https://noiseprotocol.org/noise.html#interactive-handshake-patterns-fundamental)**

12 interactive handskake patterns.

**[Deferred handshake patterns](https://noiseprotocol.org/noise.html#interactive-handshake-patterns-deferred)**

23 deferred handshake patterns.

### PSK mode

### Fallback mode

### Customized Handshake Pattern

To create your own handshake pattern, use the function `Register`, pass in the name and pattern in string. Once it passed all the checks, you can then use it by calling `FromString(patternName)`

Here's an example, which implements a new pattern named `NXdumb`,

```go
// This is an implemention for demonstration only. DON'T USE IT IN YOUR CODE.
package main

import (
	"fmt"

	"github.com/yyforyongyu/babble/pattern"
)

func main() {
	// Define your own name and pattern.
	name := "NXdumb"
	rawPattern := `
		-> e
		<- e, ee, se, s, es`

	// Register will validate the pattern, if invalid, an error is returned.
	err := pattern.Register(name, rawPattern)
	if err != nil {
		fmt.Println(err)
	}

	// use the pattern NXdumb
	p := pattern.FromString("NXdumb")
	fmt.Printf("The patter name is: %s\n"+
		"Pre-message pattern: %v\n"+"Message pattern: %+q",
		p.Name, p.PreMessagePattern, p.MessagePattern)
}
```

