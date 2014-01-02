// wherez (Where Zee) lets you register and discover sibling nodes in the network
// based on a shared passphrase. It uses the Mainline DHT network to advertise
// its own existence and to look for other nodes that are running with the same
// passphrase.
//
// Wherez authenticates sibling peers using an HMAC-based mechanism.
//
// Example applications:
// - find the location of your company's doozerd, Chubby or DNS servers.
// - robust way for stolen notebooks to "phone home".
// - register and locate servers in a corporate network based on function, by
// using different passphrases for the DNS server, LDAP server, etc.
//
// This software is in early stages of development.
package wherez

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"log"
	"time"

	"github.com/nictuku/dht"
)

// FindAuthenticatedPeers uses the BitTorrent DHT network to find sibling
// Wherez nodes that are using the same passphrase. Wherez will listen on the
// specified port for both TCP and UDP protocols. The port must be accessible
// from the public Internet (UPnP is not supported yet).
//
// Wherez will try aggressively to find at least minPeers as fast as possible.
//
// The passphrase will be used to authenticate remote peers. This wherez node
// will keep running indefinitely as a DHT node.
//
// If appPort is a positive number, wherez will advertise that our main application
// is on port appPort of the current host. If it's negative, it doesn't
// announce itself as a peer.
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
	defer close(c)
	ih, err := infoHash(passphrase)
	if err != nil {
		log.Println("Could not calculate infohash for the provided passphrase", err)
		return
	}
	announce := false
	if appPort > 0 {
		announce = true
		if _, err = listenAuth(port, appPort, passphrase); err != nil {
			log.Println("Could not open listener:", err)
			return
		}
	}
	// Connect to the DHT network.
	d, err := dht.NewDHTNode(port, minPeers, announce)
	if err != nil {
		log.Println("Could not create the DHT node:", err)
		return
	}
	d.AddNode("213.239.195.138:40000")
	go d.DoDHT()
	// Sends authenticated peers to channel c.
	go obtainPeers(d, passphrase, c)

	for {
		// Keeps requesting for the infohash. This is a no-op if the
		// DHT is satisfied with the number of peers it has found.
		d.PeersRequest(string(ih), true)

		time.Sleep(5 * time.Second)
	}
}

func obtainPeers(d *dht.DHT, passphrase []byte, c chan Peer) {
	for r := range d.PeersRequestResults {
		for _, peers := range r {
			for _, x := range peers {
				// A DHT peer for our infohash was found. It
				// needs to be authenticated.
				checkPeer(dht.DecodePeerAddress(x), passphrase, c)
			}
		}
	}
}

// infohash used for this wherez lookup. This should be somewhat hard to guess
// but it's not exactly a secret.
func infoHash(passphrase []byte) (dht.InfoHash, error) {
	// SHA256 of the passphrase.
   h256:= sha256.New()
	h256.Write(passphrase)
   h := h256.Sum(nil)

	// Assuming perfect rainbow databases, it's better if the infohash does not
	// give out too much about the passphrase. Take half of this hash, then
	// generate a SHA1 hash from it.
	h2 := h[0 : sha256.Size/2]

	// Mainline DHT uses sha1.
	h160:= sha1.New()
	h160.Write(h2)
	h3:=h160.Sum(nil)
	return dht.InfoHash(h3[:]), nil
}
