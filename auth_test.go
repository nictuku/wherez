package wherez

import (
	"bytes"
	"net"
	"testing"
)

type rwc struct {
	bytes.Buffer
}

func (w *rwc) Close() error {
	return nil
}

// addrLocal takes the port information from a net.Addr response and creates a
// "localhost:port" string.
func addrLocal(addr net.Addr) string {
	_, port, _ := net.SplitHostPort(addr.String())
	return net.JoinHostPort("localhost", port)
}

func TestAuth(t *testing.T) {
	// Ignore the dedupe ID check.
	allowSelfConnection = true
	passphrase := []byte("secret")
	want := "localhost:3000"

	// Starts server in the background.
	addr, err := listenAuth(0, 3000, passphrase)
	if err != nil {
		t.Fatalf("listenAuth error %v", err)
	}

	// Client.
	peer, err := verifyPeer(addrLocal(addr), passphrase)
	if err != nil {
		t.Errorf("auth: %v", err)
	}
	if peer.String() != want {
		t.Errorf("Wanted peer %v, got %v", want, peer.String())
	}
	allowSelfConnection = false
}

func TestBrokenAuth(t *testing.T) {
	// Ignore the dedupe ID check.
	allowSelfConnection = true
	passphrase := []byte("secrettwo")

	// Starts server in the background.
	addr, err := listenAuth(0, 3000, passphrase)
	if err != nil {
		t.Fatalf("listenAuth error %v", err)
	}

	// Connect to the server and tries to verify it.
	if _, err := verifyPeer(addrLocal(addr), []byte("someotherpass")); err == nil {
		t.Fatalf("Expected an error for failed auth, got nil")
	}
	allowSelfConnection = false
}
