package passwd

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
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

// Hash takes a password and return a phc-formatted hash. PHC stands for password hashing competition.
//
// Reference:
// https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
// https://crypto.stackexchange.com/questions/48935/why-use-argon2i-or-argon2d-if-argon2id-exists
func Hash(password string) (string, error) {
	if len(strings.TrimSpace(password)) == 0 {
		return "", errors.New("password cannot be empty")
	}
	salt, err := generateSalt(saltLen)
	if err != nil {
		return "", err
	}
	unencodedHash := argon2.IDKey([]byte(password), []byte(salt), time, memory, parallelism, keyLen)
	encodedHash := base64.StdEncoding.EncodeToString(unencodedHash)
	phc := fmt.Sprintf("$%s$m=%d,t=%d,p=%d$%s$%s", id, memory, time, parallelism, salt, encodedHash)
	return phc, nil
}

// Verify attempts to compare the password with the hash in constant-time compare.
func Verify(password, phc string) error {
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
