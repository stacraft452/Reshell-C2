package linuxagent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

func useEncryption(vkey, salt string) bool {
	return vkey != "" && salt != ""
}

func deriveKey(vkey, salt string) []byte {
	h := sha256.Sum256([]byte(vkey + salt))
	return h[:]
}

func EncryptLine(plaintext []byte, vkey, salt string) (string, error) {
	if !useEncryption(vkey, salt) {
		return "", errors.New("linuxagent: vkey and salt required for encryption")
	}
	key := deriveKey(vkey, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptLine(b64 string, vkey, salt string) ([]byte, error) {
	if !useEncryption(vkey, salt) {
		return nil, errors.New("linuxagent: vkey and salt required for decryption")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	key := deriveKey(vkey, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("linuxagent: ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}
