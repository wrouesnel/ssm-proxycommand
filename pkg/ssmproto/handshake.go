package ssmproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"time"
)

type ActionType string

const (
	ActionKMSEncryption ActionType = "KMSEncryption"
	ActionSessionType   ActionType = "SessionType"
)

type ActionStatus int

const (
	ActionSuccess     ActionStatus = 1
	ActionFailed      ActionStatus = 2
	ActionUnsupported ActionStatus = 3
)

// SessionTypePort is the session type of port forwarding documents such as AWS-StartSSHSession.
const SessionTypePort = "Port"

type HandshakeRequest struct {
	AgentVersion           string                  `json:"AgentVersion"`
	RequestedClientActions []RequestedClientAction `json:"RequestedClientActions"`
}

type RequestedClientAction struct {
	ActionType       ActionType      `json:"ActionType"`
	ActionParameters json.RawMessage `json:"ActionParameters"`
}

type ProcessedClientAction struct {
	ActionType   ActionType   `json:"ActionType"`
	ActionStatus ActionStatus `json:"ActionStatus"`
	ActionResult any          `json:"ActionResult"`
	Error        string       `json:"Error"`
}

type HandshakeResponse struct {
	ClientVersion          string                  `json:"ClientVersion"`
	ProcessedClientActions []ProcessedClientAction `json:"ProcessedClientActions"`
	Errors                 []string                `json:"Errors"`
}

type HandshakeComplete struct {
	HandshakeTimeToComplete time.Duration `json:"HandshakeTimeToComplete"`
	CustomerMessage         string        `json:"CustomerMessage"`
}

type SessionTypeRequest struct {
	SessionType string `json:"SessionType"`
	Properties  any    `json:"Properties"`
}

type KMSEncryptionRequest struct {
	KMSKeyID string `json:"KMSKeyId"`
}

type KMSEncryptionResponse struct {
	KMSCipherTextKey  []byte `json:"KMSCipherTextKey"`
	KMSCipherTextHash []byte `json:"KMSCipherTextHash"`
}

type EncryptionChallenge struct {
	Challenge []byte `json:"Challenge"`
}

// Encrypter holds the per-session AES-GCM keys derived from a KMS data key. The first half of
// the data key decrypts agent output; the second half encrypts client input.
type Encrypter struct {
	CipherTextKey []byte
	enc, dec      cipher.AEAD
}

const nonceSize = 12

// NewEncrypter splits a 64 byte data key into the decryption (first half) and encryption
// (second half) keys. The agent uses the halves the other way around.
func NewEncrypter(plaintext, cipherTextKey []byte) (*Encrypter, error) {
	half := len(plaintext) / 2
	dec, err := newGCM(plaintext[:half])
	if err != nil {
		return nil, err
	}
	enc, err := newGCM(plaintext[half:])
	if err != nil {
		return nil, err
	}
	return &Encrypter{CipherTextKey: cipherTextKey, enc: enc, dec: dec}, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (e *Encrypter) Encrypt(plain []byte) ([]byte, error) {
	out := make([]byte, nonceSize, nonceSize+len(plain)+e.enc.Overhead())
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return e.enc.Seal(out, out[:nonceSize], plain, nil), nil
}

func (e *Encrypter) Decrypt(data []byte) ([]byte, error) {
	if len(data) < nonceSize {
		return nil, errors.New("encrypted payload too short")
	}
	return e.dec.Open(nil, data[:nonceSize], data[nonceSize:], nil)
}
