package agent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

// useEncryption 当 VKey 与 Salt 均非空时启用流量加密
func useEncryption(vkey, salt string) bool {
	return vkey != "" && salt != ""
}

// deriveKey 从 VKey+Salt 派生 AES-256 密钥（SHA256）
func deriveKey(vkey, salt string) []byte {
	h := sha256.Sum256([]byte(vkey + salt))
	return h[:]
}

// EncryptLine 加密一行数据，输出 base64(nonce || ciphertext)，末尾无换行
func EncryptLine(plaintext []byte, vkey, salt string) (string, error) {
	if !useEncryption(vkey, salt) {
		return "", errors.New("agent/crypto: vkey and salt required for encryption")
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

// DecryptLine 解密 base64(nonce || ciphertext) 得到明文
func DecryptLine(b64 string, vkey, salt string) ([]byte, error) {
	if !useEncryption(vkey, salt) {
		return nil, errors.New("agent/crypto: vkey and salt required for decryption")
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
		return nil, errors.New("agent/crypto: ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
