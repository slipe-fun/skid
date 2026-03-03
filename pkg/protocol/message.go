package protocol

const CurrentVersion uint8 = 1

type EncryptedMessage struct {
	Version         uint8  `json:"v"`
	Sequence        uint64 `json:"sequence"`
	Ciphertext      []byte `json:"ciphertext"`
	IV              []byte `json:"iv"`
	EncapsulatedKey []byte `json:"encapsulated_key"`
	CekWrap         []byte `json:"cek_wrap"`
	CekWrapIV       []byte `json:"cek_wrap_iv"`
	CekWrapSalt     []byte `json:"cek_wrap_salt"`
	Signature       []byte `json:"signature"`
}
