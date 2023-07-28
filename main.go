package main

import (
	"os"

	"github.com/curtisnewbie/gatekeeper/gatekeeper"
)

func main() {
	gatekeeper.Bootstrap(os.Args)
}
