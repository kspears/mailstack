// Command mailctl manages accounts for the mail stack.
package main

import "os"

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr))
}
