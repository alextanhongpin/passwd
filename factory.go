package passwd

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// New returns a new argon2id hasher with default configurations if none is
// provided.
func New(opts ...Option) Argon2id {
	a := Argon2id{
		time:        time,
		memory:      memory,
		parallelism: parallelism,
		keyLen:      keyLen,
		saltLen:     saltLen,
	}
	for _, o := range opts {
		o(&a)
	}
	return a
}

// Argon2id contains the configuration for the argon2id hashing function.
type Argon2id struct {
	time        uint32
	memory      uint32
	parallelism uint8
	keyLen      uint32
	saltLen     uint32
}

type Option func(*Argon2id)

// Time sets the current time.
func Time(t uint32) Option {
	return func(a *Argon2id) {
		a.time = t
	}
}

// Memory sets the current memory.
func Memory(m uint32) Option {
	return func(a *Argon2id) {
		a.memory = m
	}
}

// Parallelism sets the current parallelism.
func Parallelism(p uint8) Option {
	return func(a *Argon2id) {
		a.parallelism = p
	}
}

// SaltLen sets the current salt len.
func SaltLen(s uint32) Option {
	return func(a *Argon2id) {
		a.saltLen = s
	}
}

// KeyLen sets the current key len.
func KeyLen(k uint32) Option {
	return func(a *Argon2id) {
		a.keyLen = k
	}
}

// Hash hashes a raw-text password and return the hashed password.
func (a *Argon2id) Hash(password string) (string, error) {
	if len(strings.TrimSpace(password)) == 0 {
		return "", errors.New("password cannot be empty")
	}
	salt, err := generateSalt(a.saltLen)
	if err != nil {
		return "", err
	}
	unencodedHash := argon2.IDKey([]byte(password), []byte(salt), a.time, a.memory, a.parallelism, a.keyLen)
	encodedHash := base64.StdEncoding.EncodeToString(unencodedHash)
	phc := fmt.Sprintf("$%s$m=%d,t=%d,p=%d$%s$%s", id, a.memory, a.time, a.parallelism, salt, encodedHash)
	return phc, nil
}

// Verify attempts to compare the password with the hash in constant-time compare.
func (a *Argon2id) Verify(password, phc string) error {
	if len(password) == 0 || len(phc) == 0 {
		return errors.New("arguments len cannot be zero")
	}
	parts := strings.Split(phc[1:], "$")
	if len(parts) != 4 {
		return errors.New("invalid hash format")
	}
	var (
		pid         = parts[0]
		params      = parts[1]
		salt        = parts[2]
		encodedHash = parts[3]
	)
	if pid != id {
		return errors.New("unknown password hashing function identifier")
	}
	hash, err := base64.StdEncoding.DecodeString(encodedHash)
	if err != nil {
		return err
	}

	re := regexp.MustCompile(`^m=([0-9]+),t=([0-9]+),p=([0-9]+)$`)
	values := re.FindStringSubmatch(params)
	if len(values) != 4 {
		return errors.New("incorrect params length")
	}

	var (
		// The first match is the match of the entire expression.
		m, _ = strconv.ParseUint(values[1], 10, 32)
		t, _ = strconv.ParseUint(values[2], 10, 32)
		p, _ = strconv.ParseUint(values[3], 10, 8)
	)

	computedHash := argon2.IDKey([]byte(password), []byte(salt), uint32(t), uint32(m), uint8(p), keyLen)
	if subtle.ConstantTimeCompare(hash, computedHash) != 1 {
		return errors.New("password do not match")
	}
	return nil
}
