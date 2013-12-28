package wherez

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/nictuku/dht"
)

var (
	// Identifies wherez TCP messages.
	magicHeader = []byte("wherez")
	// dedupe is needed to ignore connections from self.
	dedupe []byte
	// If true, connections to self are allowed - used for testing.
	allowSelfConnection = false
)

const (
	messageLen = 20
	dedupeLen  = 10
)

func init() {
	var err error
	dedupe, err = randMsg()
	if err != nil {
		log.Fatalln("could not generate a dedupe id:", err)
	}
	dedupe = dedupe[0:dedupeLen]
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

// Connect on that peer's TCP port and authenticate. Alice starts a
// conversation with Bob.
//
// A: Provides a challenge.
// B: Provides a response, authenticated with the shared secret.
//
// A: Requests port number information.
// B: Provides the application port number.
//
// Result: Alice now knows that bob:portX is a valid member of the connection pool.
//
// In the real world, the above is done in only one message each way. Protocol:
// - sends initial messsage of 36 bytes, containing:
//   ~ magicHeader with "wherez" ASCII encoded.
//   ~ 10 byte dedupe ID, which the remote node uses to identify
//   connection to self.
//   ~ 20 bytes challenge.
// - the other endpoint sends a 20 bytes message containing 2 bytes
// relative to the application port, plus 32 bytes of message MAC, calculated from
// the 20 bytes of client challenge.
// The MAC should be generated using the shared passphrase.

type Challenge struct {
	MagicHeader [6]byte
	Dedupe      [10]byte
	Challenge   [20]byte
}

func newChallenge() (m Challenge, err error) {
	//m = Challenge{}
	copy(m.MagicHeader[:], magicHeader[:])
	copy(m.Dedupe[:], dedupe[:])
	challenge, err := randMsg()
	if err != nil {
		return
	}
	copy(m.Challenge[:], challenge[:])
	return
}

func checkPeer(addr string, passphrase []byte, c chan Peer) {
	if peer, err := verifyPeer(addr, passphrase); err == nil {
		c <- peer
	}

}

// verifyPeer connects to a host:port address specified in peer and sends it a
// cryptographic challenge. If the peer responds with a valid MAC that appears
// to have been generated with the shared secret in passphrase, consider it a
// valid Peer and returns the details. If the connection fails or the peer
// authentication fails, returns an error.
func verifyPeer(peer string, passphrase []byte) (p Peer, err error) {
	conn, err := net.Dial("tcp", peer)
	if err != nil {
		return
	}
	defer conn.Close()
	var challenge Challenge
	challenge, err = newChallenge()
	if err != nil {
		// log.Printf("auth newChallenge error %v", err)
		return
	}
	if err = binary.Write(conn, binary.LittleEndian, challenge); err != nil {
		// The other side is either unreachable or we connected to
		// ourselves and closed the connection.
		return
	}
	in := new(Response)
	if err = binary.Read(conn, binary.LittleEndian, in); err != nil {
		// log.Println("auth could not read response from conn:", err)
		return
	}
	if !checkMAC(challenge.Challenge[:], in.MAC[:], passphrase) {
		return p, fmt.Errorf("Invalid challenge response")
	}
	host, _, err := net.SplitHostPort(peer)
	if err != nil {
		return
	}
	return Peer{Addr: fmt.Sprintf("%v:%v", host, in.Port)}, nil
}

func randMsg() ([]byte, error) {
	b := make([]byte, 20)
	_, err := rand.Read(b)
	return b, err
}

func listenAuth(port, appPort int, passphrase []byte) (net.Addr, error) {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{Port: port})
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Println("listenAuth accept error. Stopping listener.", err)
				return
			}
			go handleConn(conn, appPort, passphrase)
		}
	}()
	return ln.Addr(), nil
}

// Response containing proof that the server (Bob) knows the shared secret and
// the application port information required by the client.
type Response struct {
	Port uint16
	// MAC of the Challenge sent by the client (Alice).
	MAC [32]byte
}

func handleConn(conn io.ReadWriteCloser, appPort int, passphrase []byte) {
	// Everything is done with one packet in and one packet out, so close
	// the connection after this function ends.
	defer conn.Close()

	// Parse the incoming packet.
	in := new(Challenge)
	err := binary.Read(conn, binary.LittleEndian, in)
	if err != nil {
		return
	}
	// Verify if the magic header is correct. Several DHT nodes will connect
	// to whatever peer they believe exist, most likely to scrape their
	// content. But we're not BitTorrent clients, so we just close the
	// connection. This shouldn't cause damage to the network because we're
	// not pretending to be peers for a bittorrent infohash. So these
	// spurious incoming connections are from misbehaving clients.
	if !bytes.Equal(in.MagicHeader[:], magicHeader) {
		// Not a wherez peer.
		return
	}
	// dedupe is a small byte array generated on initialization that
	// identifies this server. If the incoming request has the same dedupe ID,
	// it means it's trying to connect to itself. That's a normal thing, but
	// obviously useless, so close the connection.
	// To blacklist the address on the client side, the protocol would have
	// to have another step for the error feedback and for now that doesn't
	// seem worth it.
	if !allowSelfConnection && bytes.Equal(in.Dedupe[:], dedupe) {
		// Connection to self. Closing.
		return
	}
	// Calculate the challenge response.
	mac := hmac.New(sha256.New, passphrase)
	mac.Write(in.Challenge[:])

	// Create the response packet.
	response := Response{Port: uint16(appPort)}
	copy(response.MAC[:], mac.Sum(nil))

	if err = binary.Write(conn, binary.LittleEndian, response); err != nil {
		// log.Println("handleConn failed to write to remote peer:", err)
		return
	}
}

func checkMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}
