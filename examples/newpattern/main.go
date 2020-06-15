// This is an implemention for demonstration only.
package main

import (
	"fmt"

	"github.com/crypto-y/babble/pattern"
)

func main() {
	// Register a dumb pattern
	name := "YY"
	rawPattern := `
		<- s
		-> s
		...
		-> e
		<- e, ee, es`

	// Register will validate the pattern, if invalid, an error is returned.
	err := pattern.Register(name, rawPattern)
	if err != nil {
		fmt.Println(err)
	}

	// use the pattern NKpsk0
	p, _ := pattern.FromString("YY")
	fmt.Printf("The patter name is: %s\n"+
		"Pre-message pattern: %v\n"+"Message pattern: %+q\n",
		p.Name, p.PreMessagePattern, p.MessagePattern)
}
