package wherez

import (
	"fmt"
	"testing"
)

func TestInfoHash(t *testing.T) {
	ih, err := infoHash([]byte("aaaaa"))
	if err != nil {
		t.Errorf("infoHash error: %v", err)
	}
	if fmt.Sprintf("%x", ih) != "97207c9437e672af8e1731f6a7200a78623886ea" {
		t.Errorf("Unexpected ih: %x", ih)
	}
}

func TestFindPeers(t *testing.T) {
	c := FindAuthenticatedPeers(60000, 1, []byte("abacate"))
	for p := range c {
		t.Logf("Found %v", p.String())
	}
}
