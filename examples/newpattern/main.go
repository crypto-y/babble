package main

import (
	"fmt"

	"github.com/yyforyongyu/noise/pattern"
)

func main() {
	// Register a psk0 with NK
	name := "NKpsk0"
	rawPattern := `
		<- s
		...
		-> psk, e, es
		<- e, ee`

	// Register will validate the pattern, if invalid, an error is returned.
	err := pattern.Register(name, rawPattern)
	if err != nil {
		fmt.Println(err)
	}

	// use the pattern NKpsk0
	p, _ := pattern.FromString("NKpsk0")
	fmt.Printf("The patter name is: %s\n"+
		"Pre-message pattern: %v\n"+"Message pattern: %+q",
		p.Name, p.PreMessagePattern, p.MessagePattern)
}
