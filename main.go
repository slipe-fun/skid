package main

import (
	"fmt"

	"github.com/slipe-fun/skid/internal/crypto"
	"github.com/slipe-fun/skid/pkg/identity"
	"github.com/slipe-fun/skid/pkg/protocol"
)

func main() {
	alicePrivateKeys, alicePublicKeys, err := identity.NewUser()
	if err != nil {
		panic(err)
	}

	bobPrivateKeys, bobPublicKeys, err := identity.NewUser()
	if err != nil {
		panic(err)
	}

	chatKey, err := crypto.RandomBytes(32)
	if err != nil {
		panic(err)
	}

	encrypted, err := protocol.Encrypt(chatKey, alicePrivateKeys, bobPublicKeys)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Encrypted key: %s\n", string(chatKey))

	decrypted, err := protocol.Decrypt(encrypted, bobPrivateKeys, alicePublicKeys)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted key: %s\n", string(decrypted))
}
