package protocol

import "github.com/cloudflare/circl/dh/x448"

type InitialMessage struct {
	IK_Pub          x448.Key
	EK_Pub          x448.Key
	KyberCiphertext []byte
}
