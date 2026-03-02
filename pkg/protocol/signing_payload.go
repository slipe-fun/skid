package protocol

import (
	"encoding/json"

	"github.com/slipe-fun/skid/pkg/identity"
)

func (m *EncryptedMessage) signingPayload(senderPublicKeys *identity.UserPublic) ([]byte, error) {
	tmp := struct {
		EncryptedMessage
		identity.UserPublic
	}{
		EncryptedMessage: *m,
		UserPublic:       *senderPublicKeys,
	}
	tmp.Signature = nil
	return json.Marshal(tmp)
}
