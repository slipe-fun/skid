package protocol

const CurrentVersion uint8 = 1

const (
	MessageTypePreKey  uint8 = 1
	MessageTypeRatchet uint8 = 2
)

type PreKeyMessage struct {
	Version   uint8  `json:"v"`
	Type      uint8  `json:"t"`
	SessionID []byte `json:"sid,omitempty"`

	IKPub           []byte `json:"ik"`
	EKPub           []byte `json:"ek"`
	KyberCiphertext []byte `json:"k_ct"`

	SPKID  uint32 `json:"spk_id"`
	OPKID  uint32 `json:"opk_id,omitempty"`
	PQPKID uint32 `json:"pqpk_id,omitempty"`

	Message *RatchetMessage `json:"msg"`
}

type RatchetMessage struct {
	Version   uint8  `json:"v"`
	Type      uint8  `json:"t"`
	SessionID []byte `json:"sid,omitempty"`

	RatchetPub []byte `json:"r_pub"`
	Index      uint32 `json:"idx"`
	PrevIdx    uint32 `json:"p_idx"`

	Nonce      []byte `json:"n"`
	Ciphertext []byte `json:"ct"`
}
