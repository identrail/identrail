package secretstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	// AlgorithmAES256GCM is the only connector secret envelope algorithm supported today.
	AlgorithmAES256GCM = "AES-256-GCM"
	envelopeVersion    = 1
	aes256KeySize      = 32
	gcmNonceSize       = 12
	ephemeralVersion   = "ephemeral-v1"
)

var keyVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

// KeyMaterial is one versioned data-encryption key. The final key passed to
// NewManager is used for new encryptions; earlier keys remain available for decrypt.
type KeyMaterial struct {
	Version string
	Key     []byte
}

// Envelope stores ciphertext plus the minimum metadata needed for decryption
// and rotation decisions. It intentionally never stores plaintext.
type Envelope struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	KeyVersion string `json:"key_version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// Manager encrypts and decrypts connector secret envelopes.
type Manager struct {
	activeVersion string
	keys          map[string][]byte
}

// NewManager builds an envelope manager from versioned 256-bit keys.
func NewManager(materials []KeyMaterial) (*Manager, error) {
	if len(materials) == 0 {
		return nil, fmt.Errorf("connector secret keyset must include at least one key")
	}
	keys := make(map[string][]byte, len(materials))
	activeVersion := ""
	for _, material := range materials {
		version := strings.TrimSpace(material.Version)
		if !keyVersionPattern.MatchString(version) {
			return nil, fmt.Errorf("connector secret key version is invalid")
		}
		if len(material.Key) != aes256KeySize {
			return nil, fmt.Errorf("connector secret keys must be 32 bytes")
		}
		if _, exists := keys[version]; exists {
			return nil, fmt.Errorf("connector secret key versions must be unique")
		}
		keyCopy := append([]byte(nil), material.Key...)
		keys[version] = keyCopy
		activeVersion = version
	}
	return &Manager{activeVersion: activeVersion, keys: keys}, nil
}

// NewEphemeralManager creates an in-memory key manager for local and test use.
// Deployments that persist connector secrets should configure a stable keyset.
func NewEphemeralManager() *Manager {
	key := make([]byte, aes256KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic("secretstore.NewEphemeralManager: failed to read random bytes")
	}
	manager, err := NewManager([]KeyMaterial{{Version: ephemeralVersion, Key: key}})
	if err != nil {
		panic("secretstore.NewEphemeralManager: failed to initialize manager")
	}
	return manager
}

// ParseKeySet parses IDENTRAIL_CONNECTOR_SECRET_KEYS entries formatted as
// version:base64-encoded-32-byte-key, separated by commas or semicolons.
func ParseKeySet(raw string) ([]KeyMaterial, error) {
	normalized := strings.TrimSpace(raw)
	if normalized == "" {
		return nil, nil
	}
	fields := strings.FieldsFunc(normalized, func(r rune) bool {
		return r == ',' || r == ';'
	})
	materials := make([]KeyMaterial, 0, len(fields))
	for _, field := range fields {
		trimmed := strings.TrimSpace(field)
		if trimmed == "" {
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("connector secret key entries must use version:base64-key format")
		}
		version := strings.TrimSpace(parts[0])
		encoded := strings.TrimSpace(parts[1])
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			key, err = base64.RawStdEncoding.DecodeString(encoded)
		}
		if err != nil {
			return nil, fmt.Errorf("connector secret key material must be base64")
		}
		materials = append(materials, KeyMaterial{Version: version, Key: key})
	}
	if len(materials) == 0 {
		return nil, nil
	}
	return materials, nil
}

// ActiveKeyVersion returns the key version used for newly encrypted secrets.
func (m *Manager) ActiveKeyVersion() string {
	if m == nil {
		return ""
	}
	return m.activeVersion
}

// Encrypt seals plaintext with AES-256-GCM and associated data.
func (m *Manager) Encrypt(plaintext []byte, associatedData []byte) (Envelope, error) {
	if m == nil {
		return Envelope{}, fmt.Errorf("connector secret manager is not configured")
	}
	activeKey := m.keys[m.activeVersion]
	if len(activeKey) != aes256KeySize {
		return Envelope{}, fmt.Errorf("active connector secret key is unavailable")
	}
	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Envelope{}, fmt.Errorf("generate connector secret nonce: %w", err)
	}
	gcm, err := newGCM(activeKey)
	if err != nil {
		return Envelope{}, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, associatedData)
	return Envelope{
		Version:    envelopeVersion,
		Algorithm:  AlgorithmAES256GCM,
		KeyVersion: m.activeVersion,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

// Decrypt opens an encrypted connector secret envelope.
func (m *Manager) Decrypt(envelope Envelope, associatedData []byte) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("connector secret manager is not configured")
	}
	if envelope.Version != envelopeVersion || envelope.Algorithm != AlgorithmAES256GCM {
		return nil, fmt.Errorf("unsupported connector secret envelope")
	}
	key := m.keys[strings.TrimSpace(envelope.KeyVersion)]
	if len(key) != aes256KeySize {
		return nil, fmt.Errorf("connector secret key version is unavailable")
	}
	if len(envelope.Nonce) != gcmNonceSize || len(envelope.Ciphertext) == 0 {
		return nil, fmt.Errorf("connector secret envelope is invalid")
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, associatedData)
	if err != nil {
		return nil, fmt.Errorf("decrypt connector secret envelope: %w", err)
	}
	return plaintext, nil
}

// NeedsRotation reports whether an envelope was sealed with a non-active key.
func (m *Manager) NeedsRotation(envelope Envelope) bool {
	if m == nil {
		return true
	}
	return strings.TrimSpace(envelope.KeyVersion) != strings.TrimSpace(m.activeVersion)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize connector secret cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize connector secret gcm: %w", err)
	}
	return gcm, nil
}
