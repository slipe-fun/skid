package crypto

import (
	"crypto/rand"
	"encoding/binary"
)

func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func AppendWithLength(parts ...[]byte) []byte {
	var res []byte
	for _, p := range parts {
		length := make([]byte, 4)
		binary.BigEndian.PutUint32(length, uint32(len(p)))
		res = append(res, length...)
		res = append(res, p...)
	}
	return res
}
