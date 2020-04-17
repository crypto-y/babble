package main

import (
	"fmt"

	"github.com/yyforyongyu/noise/pattern"
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
