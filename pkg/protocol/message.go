package protocol

const CurrentVersion uint8 = 1

type KeyExchangeMessage struct {
	Version uint8 `json:"v"`

	EphemeralX448   []byte `json:"e_x448,omitempty"`
	KyberCiphertext []byte `json:"k_ct,omitempty"`
	OneTimePreKeyID uint32 `json:"otpk_id,omitempty"`

	RatchetPub []byte `json:"r_pub"`
	Index      uint32 `json:"idx"`
	PrevIdx    uint32 `json:"p_idx"`

	Ciphertext []byte `json:"ct"`
	IV         []byte `json:"iv"`
}
