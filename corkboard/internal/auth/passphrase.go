package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
)

const (
	MinLen = 12

	MaxLen = 256

	Iterations = 600_000

	scheme  = "pbkdf2-sha256"
	saltLen = 16
	keyLen  = 32
)

var b64 = base64.RawStdEncoding

func CheckPolicy(p string) error {
	if len(p) < MinLen {
		return fmt.Errorf("passphrase must be at least %d characters", MinLen)
	}
	if len(p) > MaxLen {
		return fmt.Errorf("passphrase must be at most %d characters", MaxLen)
	}
	if strings.TrimSpace(p) != p {
		return errors.New("passphrase must not start or end with a space")
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] > 0x7e {
			return errors.New("passphrase must be printable ASCII (letters, digits, spaces, punctuation)")
		}
	}
	return nil
}

func Hash(p string) (string, error) { return HashCost(p, Iterations) }

func HashCost(p string, iter int) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("passphrase salt: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, p, salt, iter, keyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s$%d$%s$%s", scheme, iter, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

type Verifier struct {
	iter     int
	salt     []byte
	key      []byte
	verified atomic.Pointer[[32]byte]
}

func NewVerifier(hash string) (*Verifier, error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != scheme {
		return nil, fmt.Errorf("not a %s hash", scheme)
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return nil, errors.New("bad iteration count")
	}
	salt, err := b64.DecodeString(parts[2])
	if err != nil || len(salt) < 8 {
		return nil, errors.New("bad salt")
	}
	key, err := b64.DecodeString(parts[3])
	if err != nil || len(key) != keyLen {
		return nil, errors.New("bad key")
	}
	return &Verifier{iter: iter, salt: salt, key: key}, nil
}

func (v *Verifier) Check(p string) bool {
	if p == "" || len(p) > MaxLen {
		return false
	}
	sum := sha256.Sum256([]byte(p))
	if c := v.verified.Load(); c != nil && subtle.ConstantTimeCompare(sum[:], c[:]) == 1 {
		return true
	}
	key, err := pbkdf2.Key(sha256.New, p, v.salt, v.iter, keyLen)
	if err != nil || subtle.ConstantTimeCompare(key, v.key) != 1 {
		return false
	}
	v.verified.Store(&sum)
	return true
}
