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

	b.WriteString("SKID-PROTOCOL-V1")

	b.WriteByte(message.Version)
	binary.Write(&b, binary.BigEndian, message.Epoch)

	senderECDHKeyHash := sha256.Sum256(senderPub.ECDHKey)
	receiverECDHKeyHash := sha256.Sum256(receiverPub.ECDHKey)
	b.Write(senderECDHKeyHash[:])
	b.Write(receiverECDHKeyHash[:])

	senderKyberKeyHash := sha256.Sum256(senderPub.KyberKey)
	receiverKyberKeyHash := sha256.Sum256(receiverPub.ECDHKey)
	b.Write(senderKyberKeyHash[:])
	b.Write(receiverKyberKeyHash[:])

	b.WriteString(senderID)
	b.WriteByte('|')
	b.WriteString(receiverID)

	b.Write(message.EncapsulatedKey)

	b.Write(message.CekWrapSalt)

	return b.Bytes()
}
