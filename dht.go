package wherez

import (
	"crypto/hmac"
	"crypto/sha256"
	"log"

	"github.com/nictuku/dht"
)

func obtainPeers(d *dht.DHT, c chan Peer) {
	for r := range d.PeersRequestResults {
		for _, peers := range r {
			for _, x := range peers {
				log.Printf("Address found %v", dht.DecodePeerAddress(x))
				c <- Peer{Addr: dht.DecodePeerAddress(x)}
			}
		}
	}
}

func checkMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}
