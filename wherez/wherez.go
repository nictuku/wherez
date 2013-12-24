package main

import (
	"flag"
	"log"

	"github.com/nictuku/wherez"
)

func main() {
	flag.Parse()
	if len(flag.Args()) != 1 {
		log.Fatalln("Usage: wherez [options] <passphrase>")
	}
	passphrase := flag.Arg(0)
	c := wherez.FindAuthenticatedPeers(60000, 1, []byte(passphrase))
	for p := range c {
		log.Printf("Found %v", p.String())
	}
}
