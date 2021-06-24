package main

import (
	"github.com/treeforest/ca-example/ca"
	"log"
)

func main() {
	CA := ca.NewCA()
	log.Fatal(CA.Serve())
}
