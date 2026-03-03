package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"github.com/slipe-fun/skid/pkg/identity"
)

func (m *EncryptedMessage) signingPayload(receiverPub *identity.UserPublic) ([]byte, error) {
	var b bytes.Buffer

	domainHash := sha256.Sum256([]byte("SKID-PROTOCOL-V1"))
	b.Write(domainHash[:])
	b.WriteByte(m.Version)
	binary.Write(&b, binary.BigEndian, m.Sequence)

	writeWithLen := func(data []byte) {
		binary.Write(&b, binary.BigEndian, uint32(len(data)))
		b.Write(data)
	}

	writeWithLen(receiverPub.ECDHKey)
	writeWithLen(receiverPub.KyberKey)
	writeWithLen(m.IV)
	writeWithLen(m.CekWrap)
	writeWithLen(m.EncapsulatedKey)
	writeWithLen(m.CekWrapIV)
	writeWithLen(m.CekWrapSalt)
	writeWithLen(m.Ciphertext)

	return b.Bytes(), nil
}
