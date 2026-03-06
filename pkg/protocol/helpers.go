package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"github.com/slipe-fun/skid/pkg/identity"
)

func writeWithLen(b *bytes.Buffer, data []byte) {
	_ = binary.Write(b, binary.BigEndian, uint32(len(data)))
	b.Write(data)
}

func GenerateKDFContext(senderSessionID, receiverSessionID string, senderPublicKeys, receiverPublicKeys *identity.UserPublic, wrapSaltReceiver []byte) []byte {
	var b bytes.Buffer

	domainHash := sha256.Sum256([]byte("SKID-PROTOCOL-V1-KDF"))
	b.Write(domainHash[:])

	writeWithLen(&b, []byte(senderSessionID))
	writeWithLen(&b, []byte(receiverSessionID))

	writeWithLen(&b, senderPublicKeys.ECDHKey)
	writeWithLen(&b, senderPublicKeys.KyberKey)
	writeWithLen(&b, senderPublicKeys.Ed25519Key)

	writeWithLen(&b, receiverPublicKeys.ECDHKey)
	writeWithLen(&b, receiverPublicKeys.KyberKey)
	writeWithLen(&b, receiverPublicKeys.Ed25519Key)

	writeWithLen(&b, wrapSaltReceiver)

	return b.Bytes()
}

func (m *EncryptedMessage) signingPayload(senderPublicKeys *identity.UserPublic, receiverPublicKeys *identity.UserPublic, senderSessionID, receiverSessionID []byte) []byte {
	var b bytes.Buffer

	domainHash := sha256.Sum256([]byte("SKID-PROTOCOL-V1"))
	b.Write(domainHash[:])
	b.WriteByte(m.Version)
	binary.Write(&b, binary.BigEndian, m.Epoch)

	writeWithLen(&b, receiverSessionID)
	writeWithLen(&b, senderSessionID)

	writeWithLen(&b, senderPublicKeys.ECDHKey)
	writeWithLen(&b, senderPublicKeys.KyberKey)
	writeWithLen(&b, senderPublicKeys.Ed25519Key)

	writeWithLen(&b, receiverPublicKeys.ECDHKey)
	writeWithLen(&b, receiverPublicKeys.KyberKey)
	writeWithLen(&b, receiverPublicKeys.Ed25519Key)

	writeWithLen(&b, m.SenderEphemeralECDH)
	writeWithLen(&b, m.IV)
	writeWithLen(&b, m.CekWrap)
	writeWithLen(&b, m.EncapsulatedKey)
	writeWithLen(&b, m.CekWrapIV)
	writeWithLen(&b, m.CekWrapSalt)
	writeWithLen(&b, m.Ciphertext)

	return b.Bytes()
}

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

	writeWithLen(&b, senderPub.ECDHKey)
	writeWithLen(&b, senderPub.KyberKey)
	writeWithLen(&b, senderPub.Ed25519Key)

	writeWithLen(&b, receiverPub.ECDHKey)
	writeWithLen(&b, receiverPub.KyberKey)
	writeWithLen(&b, receiverPub.Ed25519Key)

	writeWithLen(&b, []byte(senderID))
	writeWithLen(&b, []byte(receiverID))

	writeWithLen(&b, message.SenderEphemeralECDH)
	writeWithLen(&b, message.EncapsulatedKey)
	writeWithLen(&b, message.CekWrapSalt)

	return b.Bytes()
}
