package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"github.com/slipe-fun/skid/pkg/identity"
)

func (m *EncryptedMessage) signingPayload(senderPublicKeys *identity.UserPublic, receiverPublicKeys *identity.UserPublic, receiverID, senderID []byte) ([]byte, error) {
	var b bytes.Buffer

	domainHash := sha256.Sum256([]byte("SKID-PROTOCOL-V1"))
	b.Write(domainHash[:])
	b.WriteByte(m.Version)
	binary.Write(&b, binary.BigEndian, m.Epoch)

	writeWithLen := func(data []byte) {
		binary.Write(&b, binary.BigEndian, uint32(len(data)))
		b.Write(data)
	}

	writeWithLen(receiverID)
	writeWithLen(senderID)
	writeWithLen(senderPublicKeys.ECDHKey)
	writeWithLen(senderPublicKeys.KyberKey)
	writeWithLen(receiverPublicKeys.ECDHKey)
	writeWithLen(receiverPublicKeys.KyberKey)
	writeWithLen(m.IV)
	writeWithLen(m.CekWrap)
	writeWithLen(m.EncapsulatedKey)
	writeWithLen(m.CekWrapIV)
	writeWithLen(m.CekWrapSalt)
	writeWithLen(m.Ciphertext)

	return b.Bytes(), nil
}
