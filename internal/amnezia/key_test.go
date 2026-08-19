package amnezia

import "testing"

func TestKeyRoundTrip(t *testing.T) {
	key, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseKey(key.String())
	if err != nil {
		t.Fatal(err)
	}
	if parsed != key {
		t.Fatal("key did not round-trip")
	}
}

func TestParseKeyRejectsInvalidLength(t *testing.T) {
	if _, err := ParseKey("AA=="); err == nil {
		t.Fatal("expected invalid key error")
	}
}
