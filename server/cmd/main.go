package main

import (
	"github.com/treeforest/ca-example/server"
	"log"
)

func main() {
	s := server.NewServer()

	s.GetCertificateFromCA()

	log.Fatal(s.Serve())
}
