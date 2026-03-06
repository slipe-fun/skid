package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"github.com/slipe-fun/skid/pkg/identity"
)

func GenerateKDFContext(senderSessionID, receiverSessionID string, senderPublicKeys, receiverPublicKeys *identity.UserPublic, wrapSaltReceiver []byte) []byte {
	var b bytes.Buffer

	domainHash := sha256.Sum256([]byte("SKID-PROTOCOL-V1-KDF"))
	b.Write(domainHash[:])

	writeWithLen := func(data []byte) {
		binary.Write(&b, binary.BigEndian, uint32(len(data)))
		b.Write(data)
	}

	writeWithLen([]byte(senderSessionID))
	writeWithLen([]byte(receiverSessionID))

	writeWithLen(senderPublicKeys.ECDHKey)
	writeWithLen(senderPublicKeys.KyberKey)
	writeWithLen(senderPublicKeys.Ed25519Key)

	writeWithLen(receiverPublicKeys.ECDHKey)
	writeWithLen(receiverPublicKeys.KyberKey)
	writeWithLen(receiverPublicKeys.Ed25519Key)

	writeWithLen(wrapSaltReceiver)

	return b.Bytes()
}
