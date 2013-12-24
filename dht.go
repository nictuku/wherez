package wherez

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/nictuku/dht"
)

var (
	// Identifies wherez TCP messages.
	magicHeader = []byte("wherez")
	// dedupe is needed to ignore connections from self.
	dedupe []byte
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
				auth(dht.DecodePeerAddress(x), passphrase, c)
			}
		}
	}
}

func auth(peer string, passphrase []byte, c chan Peer) {
	// Connect on that peer's TCP port and authenticate. Protocol:
	// - send the 10 byte dedupe ID. If remote node doesn't like it, like
	// when it detects a connect to self, the conn is closed.
	// - the other endpoint sends a 20 bytes message containing 2 bytes
	// relative to the application port, plus 18 random bytes, plus 32
	// bytes of message MAC.
	// The MAC should be generated using the shared passphrase.
	conn, err := net.Dial("tcp", peer)
	if err != nil {
		return
	}
	defer conn.Close()
	n, err := conn.Write(append(magicHeader, dedupe...))
	if err != nil {
		// The other side is either unreachable or we connected to
		// ourselves and closed the connection.
		return
	}
	if n != 16 { // len(magicHeader) + dedupeLen.
		log.Printf("weird, written %d, wanted %d", n, len(dedupe))
		return
	}
	buf := make([]byte, messageLen+sha256.Size) // message + MAC
	n, err = conn.Read(buf)
	if err != nil {
		// The other side is either unreachable or we connected to
		// ourselves and closed the connection.
		return
	}
	// The first two bytes are the port number.
	appPort := binary.LittleEndian.Uint16(buf)
	if !checkMAC(buf[0:20], buf[20:20+sha256.Size], passphrase) {
		// Invalid message MAC. Ignoring peer.
		return
	}
	host, _, err := net.SplitHostPort(peer)
	if err != nil {
		return
	}
	c <- Peer{Addr: fmt.Sprintf("%v:%v", host, appPort)}
	return
}

func randMsg() ([]byte, error) {
	b := make([]byte, 20)
	_, err := rand.Read(b)
	return b, err
}

func listenAuth(port, appPort int, passphrase []byte) error {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{Port: port})
	if err != nil {
		return err
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("listenAuth accept error", err)
			return err
		}
		go handleConn(conn, appPort, passphrase)
	}
}

func handleConn(conn net.Conn, appPort int, passphrase []byte) {
	defer conn.Close()

	// The header should contain the magicHeader + the dedupe bytes.
	headerCheck := make([]byte, len(magicHeader)+dedupeLen)
	_, err := conn.Read(headerCheck)
	if err != nil {
		log.Println("handleConn read error", err)
		return
	}
	if !bytes.Equal(headerCheck[0:len(magicHeader)], magicHeader) {
		// Not a wherez peer.
		return
	}
	if bytes.Equal(headerCheck[len(magicHeader):], dedupe) {
		// Connection to self. Closing.
		return
	}
	msg, err := randMsg()
	if err != nil {
		log.Println("auth could not generate random bytes:", err)
		return
	}
	// Write the appPort in the first two bytes.
	binary.LittleEndian.PutUint16(msg, uint16(appPort))
	mac := hmac.New(sha256.New, passphrase)
	mac.Write(msg)
	messageMAC := mac.Sum(nil)
	msg = append(msg, messageMAC...)
	_, err = conn.Write(msg)
	if err != nil {
		log.Println("auth failed to write to remote peer:", err)
		return
	}
}

func checkMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}
