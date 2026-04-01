package crypto

import (
	"crypto/sha512"
	"io"
	"log"

	"golang.org/x/crypto/hkdf"
)

func DeriveHybridKey(dh1, dh2, dh3, dh4, pqSecret []byte) []byte {
	var keyMaterial []byte

	keyMaterial = append(keyMaterial, dh1...)
	keyMaterial = append(keyMaterial, dh2...)
	keyMaterial = append(keyMaterial, dh3...)
	keyMaterial = append(keyMaterial, dh4...)
	keyMaterial = append(keyMaterial, pqSecret...)

	info := []byte("SKID-Hybrid")
	hkdfReader := hkdf.New(sha512.New, keyMaterial, nil, info)

	finalKey := make([]byte, 32)
	_, err := io.ReadFull(hkdfReader, finalKey)
	if err != nil {
		log.Fatal(err)
	}

	return finalKey
}
