package protocol

import "encoding/json"

func (m *EncryptedMessage) signingPayload() ([]byte, error) {
	tmp := *m
	tmp.Signature = nil
	return json.Marshal(tmp)
}
