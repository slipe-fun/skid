package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"github.com/slipe-fun/skid/pkg/identity"
)

func GenerateAAD(
	message EncryptedMessage,
	senderID, receiverID string,
	senderPub *identity.UserPublic,
	receiverPub *identity.UserPublic,
) []byte {
	var b bytes.Buffer

	domainHash := sha256.Sum256([]byte("SKID-PROTOCOL-V1-AAD"))
	b.Write(domainHash[:])
	b.WriteByte(message.Version)
	binary.Write(&b, binary.BigEndian, message.Epoch)

	writeWithLen := func(data []byte) {
		binary.Write(&b, binary.BigEndian, uint32(len(data)))
		b.Write(data)
	}

	writeWithLen(senderPub.ECDHKey)
	writeWithLen(senderPub.KyberKey)
	writeWithLen(senderPub.Ed25519Key)

	writeWithLen(receiverPub.KyberKey)
	writeWithLen(receiverPub.ECDHKey)
	writeWithLen(receiverPub.Ed25519Key)

	writeWithLen([]byte(senderID))
	writeWithLen([]byte(receiverID))

	writeWithLen(message.SenderEphemeralECDH)
	writeWithLen(message.EncapsulatedKey)
	writeWithLen(message.CekWrapSalt)

	return b.Bytes()
}
