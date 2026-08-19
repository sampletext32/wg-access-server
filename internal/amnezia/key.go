package amnezia

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

type Key [32]byte

func ParseKey(value string) (Key, error) {
	var key Key
	b, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(b) != len(key) {
		return key, errors.New("key must be base64-encoded 32 bytes")
	}
	copy(key[:], b)
	return key, nil
}

func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

func GeneratePrivateKey() (Key, error) {
	var key Key
	if _, err := rand.Read(key[:]); err != nil {
		return key, err
	}
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	return key, nil
}
