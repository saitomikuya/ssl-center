package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

// EnvelopePrefix is the version prefix on all AES-256-GCM encrypted strings.
const EnvelopePrefix = "v1:"

var (
	ErrInvalidCiphertextPrefix = errors.New("invalid ciphertext format: missing v1: prefix")
	ErrCiphertextTooShort      = errors.New("invalid ciphertext: payload shorter than nonce and auth tag")
)

// Cipher provides thread-safe AES-256-GCM authenticated encryption with AAD binding
// and supports atomic key replacement during backup restore.
type Cipher struct {
	mu   sync.RWMutex
	aead cipher.AEAD
}

// NewCipher creates a Cipher initialized with a 32-byte AES-256 key.
func NewCipher(key []byte) (*Cipher, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

// ReloadKey replaces the active AES-256-GCM key in a thread-safe manner.
func (c *Cipher) ReloadKey(key []byte) error {
	aead, err := newGCM(key)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.aead = aead
	c.mu.Unlock()
	return nil
}

// Encrypt encrypts plaintext with AES-256-GCM bound to aad (typically "table:column").
// An empty plaintext returns "" with nil error.
func (c *Cipher) Encrypt(plaintext, aad string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	c.mu.RLock()
	aead := c.aead
	c.mu.RUnlock()

	if aead == nil {
		return "", errors.New("cipher not initialized")
	}

	nonceSize := aead.NonceSize()
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate gcm nonce: %w", err)
	}

	sealed := aead.Seal(nonce, nonce, []byte(plaintext), []byte(aad))
	return EnvelopePrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt decrypts a "v1:<base64(nonce|ciphertext|tag)>" envelope bound to aad.
// An empty ciphertext returns "" with nil error.
func (c *Cipher) Decrypt(ciphertext, aad string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	if !strings.HasPrefix(ciphertext, EnvelopePrefix) {
		return "", ErrInvalidCiphertextPrefix
	}

	encoded := strings.TrimPrefix(ciphertext, EnvelopePrefix)
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext base64: %w", err)
	}

	c.mu.RLock()
	aead := c.aead
	c.mu.RUnlock()

	if aead == nil {
		return "", errors.New("cipher not initialized")
	}

	nonceSize := aead.NonceSize()
	if len(raw) < nonceSize+aead.Overhead() {
		return "", ErrCiphertextTooShort
	}

	nonce := raw[:nonceSize]
	payload := raw[nonceSize:]
	plain, err := aead.Open(nil, nonce, payload, []byte(aad))
	if err != nil {
		return "", fmt.Errorf("decrypt with aad %q: %w", aad, err)
	}
	return string(plain), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != MasterKeySize {
		return nil, fmt.Errorf("invalid AES-256 key length: got %d bytes, want %d", len(key), MasterKeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return aead, nil
}
