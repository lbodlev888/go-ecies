package ecies

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
)

func Encrypt(publicKey *ecdh.PublicKey, curve ecdh.Curve, plaintext []byte) (EncryptedData, error) {
	var encrypted_data EncryptedData
	eph_key, err := curve.GenerateKey(rand.Reader)
	if err != nil { return EncryptedData{}, fmt.Errorf("Could not generate ephemeral key: %w", err) }

	pubkey_bytes := eph_key.PublicKey().Bytes()
	encrypted_data.ephemeral_len = len(pubkey_bytes)
	encrypted_data.ephemeral_pub = make([]byte, encrypted_data.ephemeral_len)
	copy(encrypted_data.ephemeral_pub, pubkey_bytes)

	shared_secret, err := eph_key.ECDH(publicKey)
	if err != nil { return EncryptedData{}, fmt.Errorf("Could not derive shared secret: %w", err) }

	rand.Read(encrypted_data.salt[:])
	rand.Read(encrypted_data.nonce[:])

	encryption_key, err := hkdf.Key(sha256.New, shared_secret, encrypted_data.salt[:], hkdfInfoString, chacha20poly1305.KeySize)
	if err != nil { return EncryptedData{}, fmt.Errorf("Could not derive encryption key: %w", err) }

	aead, err := chacha20poly1305.New(encryption_key)
	if err != nil { return EncryptedData{}, fmt.Errorf("Could not init cipher instance: %w", err) }
	encrypted_data.ciphertext = aead.Seal(nil, encrypted_data.nonce[:], plaintext, nil)
	return encrypted_data, nil
}

func Decrypt(privateKey *ecdh.PrivateKey, curve ecdh.Curve, encData EncryptedData) ([]byte, error) {
	eph_key, err := curve.NewPublicKey(encData.ephemeral_pub)
	if err != nil { return nil, fmt.Errorf("Could not parse ephemeral key: %w", err) }

	shared_secret, err := privateKey.ECDH(eph_key)
	if err != nil { return nil, fmt.Errorf("Could not derive shared secret: %w", err) }

	encryption_key, err := hkdf.Key(sha256.New, shared_secret, encData.salt[:], hkdfInfoString, chacha20poly1305.KeySize)
	if err != nil { return nil, fmt.Errorf("Could not derive encryption key: %w", err) }

	aead, err := chacha20poly1305.New(encryption_key)
	if err != nil { return nil, fmt.Errorf("Could not init cipher instance: %w", err) }

	plaintext, err := aead.Open(nil, encData.nonce[:], encData.ciphertext, nil)
	if err != nil { return nil, fmt.Errorf("Could not decrypt data: %w", err) }
	return plaintext, nil
}
