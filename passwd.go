package passwd

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrUnknownHashFunction = errors.New("unknown password hashing function identifier")
	ErrPasswordRequired    = errors.New("password is required")
	ErrPasswordInvalid     = errors.New("password is invalid")
	ErrHashInvalid         = errors.New("hash is invalid")
)

const (
	// Salt config
	saltLen = 16

	// Argon2id config
	id          = "argon2id"
	time        = 2
	memory      = 64 * 1024
	parallelism = 4
	keyLen      = 32
)

func generateSalt(size uint32) (string, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

// Encrypt takes a password and return a phc-formatted hash. PHC stands for password hashing competition.
//
// Reference:
// https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
// https://crypto.stackexchange.com/questions/48935/why-use-argon2i-or-argon2d-if-argon2id-exists
func Encrypt(password string) (string, error) {
	return encrypt(password, parallelism, saltLen, time, memory, keyLen)
}

// Verify attempts to compare the password with the hash in constant-time compare.
func Compare(password, phc string) (bool, error) {
	return compare(password, phc, keyLen)
}

// -- helper functions

func encrypt(password string, parallelism uint8, saltLen, time, memory, keyLen uint32) (string, error) {
	password = strings.TrimSpace(password)
	if len(password) == 0 {
		return "", ErrPasswordRequired
	}
	salt, err := generateSalt(saltLen)
	if err != nil {
		return "", fmt.Errorf("generate salt failed: %w", err)
	}
	unencodedHash := argon2.IDKey([]byte(password), []byte(salt), time, memory, parallelism, keyLen)
	encodedHash := base64.StdEncoding.EncodeToString(unencodedHash)
	phc := fmt.Sprintf("$%s$m=%d,t=%d,p=%d$%s$%s", id, memory, time, parallelism, salt, encodedHash)
	return phc, nil
}

func compare(password, phc string, keyLen uint32) (bool, error) {
	password = strings.TrimSpace(password)
	phc = strings.TrimSpace(phc)

	if len(password) == 0 || len(phc) == 0 {
		return false, ErrPasswordRequired
	}
	parts := strings.Split(phc[1:], "$")
	if len(parts) != 4 {
		return false, ErrHashInvalid
	}
	var (
		pid         = parts[0]
		params      = parts[1]
		salt        = parts[2]
		encodedHash = parts[3]
	)
	if pid != id {
		return false, ErrUnknownHashFunction
	}
	hash, err := base64.StdEncoding.DecodeString(encodedHash)
	if err != nil {
		return false, err
	}
	var m, t uint32
	var p uint8
	n, err := fmt.Sscanf(params, "m=%d,t=%d,p=%d", &m, &t, &p)
	if n != 3 {
		return false, ErrHashInvalid
	}
	computedHash := argon2.IDKey([]byte(password), []byte(salt), t, m, p, keyLen)
	if subtle.ConstantTimeCompare(hash, computedHash) != 1 {
		return false, nil
	}
	return true, nil
}

func ConstantTimeCompare(s1, s2 string) bool {
	return subtle.ConstantTimeCompare([]byte(s1), []byte(s2)) == 1
}
