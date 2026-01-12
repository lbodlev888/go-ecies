package ecies

import (
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	saltLength int = 16
	hkdfInfoString string = "ecies-v2"
)

var keyLen = map[int]byte {
	65: 0x01,
	97: 0x02,
	133: 0x03,
}
var keyLenReverse = map[byte]int{}

type nonce [chacha20poly1305.NonceSize]byte
type salt [saltLength]byte

type EncryptedData struct {
	ephemeral_len int
	nonce nonce
	salt salt
	ephemeral_pub []byte
	ciphertext []byte
}

func init() {
	for k, v := range keyLen {
		keyLenReverse[v] = k
	}
}

func (en EncryptedData) Bytes() []byte {
	totalLen := chacha20poly1305.NonceSize + saltLength + en.ephemeral_len + len(en.ciphertext) + 1 //last byte for curve type association
	buf := make([]byte, totalLen)
	buf[0] = keyLen[en.ephemeral_len]
	offset := 1

	copy(buf[offset:], en.nonce[:])
	offset += chacha20poly1305.NonceSize

	copy(buf[offset:], en.salt[:])
	offset += saltLength

	copy(buf[offset:], en.ephemeral_pub)
	offset += en.ephemeral_len

	copy(buf[offset:], en.ciphertext)

	return buf
}

func (en EncryptedData) String() string {
	return base64.RawStdEncoding.EncodeToString(en.Bytes())
}

func (en *EncryptedData) LoadBytes(buf []byte) {
	l, ok := keyLenReverse[buf[0]]
	if !ok {
		panic("invalid ephemeral key tag")
	}
	en.ephemeral_len = l

	buf = buf[1:]

	copy(en.nonce[:], buf)
	buf = buf[chacha20poly1305.NonceSize:]

	copy(en.salt[:], buf)
	buf = buf[saltLength:]

	en.ephemeral_pub = make([]byte, en.ephemeral_len)
	copy(en.ephemeral_pub, buf)
	buf = buf[en.ephemeral_len:]

	en.ciphertext = make([]byte, len(buf))
	copy(en.ciphertext, buf)
}

func (en *EncryptedData) LoadString(enc_data string) error {
	buf, err := base64.RawStdEncoding.DecodeString(enc_data)
	if err != nil {
		return fmt.Errorf("Could not parse data: %w", err)
	}

	en.LoadBytes(buf)
	return nil
}
