package wherez

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"log"
	"time"

	"github.com/nictuku/dht"
)

// FindAuthenticatedPeers. Wherez will listen on the specified port for both
// TCP and UDP protocols.  The ports must be accessible from the public
// Internet (UPnP is not supported yet). Wherez will try aggressively to find
// at least minPeers as fast as possible. The passphrase will be used to
// authenticate remote peers.
func FindAuthenticatedPeers(port, appPort, minPeers int, passphrase []byte) chan Peer {
	c := make(chan Peer)
	go findAuthenticatedPeers(port, appPort, minPeers, passphrase, c)
	return c
}

type Peer struct {
	Addr string
}

func (p Peer) String() string {
	return fmt.Sprintf("%v", p.Addr)
}

func findAuthenticatedPeers(port, appPort, minPeers int, passphrase []byte, c chan Peer) {
	ih, err := infoHash(passphrase)
	if err != nil {
		log.Println("Could not calculate infohash for the provided passphrase", err)
		close(c)
		return
	}
	go listenAuth(port, appPort, passphrase)
	// Connect to the DHT network.
	d, err := dht.NewDHTNode(port, minPeers, true)
	if err != nil {
		log.Println("Could not create the DHT node:", err)
		close(c)
		return
	}
	go d.DoDHT()
	// XXX
	d.AddNode("213.239.195.138:40000")
	// Sends authenticated peers to channel c.
	go obtainPeers(d, passphrase, c)

	for {
		// Keeps requesting for the infohash. This is a no-op if the
		// DHT is satisfied with the number of peers it has found.
		d.PeersRequest(string(ih), true)

		time.Sleep(5 * time.Second)
	}
}

// infohash used for this wherez lookup. This should be somewhat hard to guess
// but it's not exactly a secret.
func infoHash(passphrase []byte) (dht.InfoHash, error) {
	// SHA256 of the passphrase.
	h := sha256.Sum256(passphrase)

	// Assuming perfect rainbow databases, it's better if the infohash does not
	// give out too much about the passphrase. Take half of this hash, then
	// generate a SHA1 hash from it.
	h2 := h[0 : sha256.Size/2]

	// Mainline DHT uses sha1.
	h3 := sha1.Sum(h2)
	return dht.InfoHash(h3[:]), nil
}
