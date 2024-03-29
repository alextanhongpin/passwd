package passwd

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

var (
	ErrUnknownHashFunction = errors.New("passwd: unknown password hashing function identifier")
	ErrPasswordRequired    = errors.New("passwd: password is required")
	ErrPasswordInvalid     = errors.New("passwd: password is invalid")
	ErrHashInvalid         = errors.New("passwd: hash is invalid")
	ErrGenerateSalt        = errors.New("passwd: generate salt failed")
	ErrBase64Decode        = errors.New("passwd: base64 decoding failed")
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

	scanArgsLen  = 3
	hashPartsLen = 4
)

func generateSalt(size uint32) (string, error) {
	salt := make([]byte, size)

	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(salt), nil
}

// Encrypt takes a password and return a phc-formatted hash. PHC stands for password hashing competition.
//
// Reference:
// https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
// https://crypto.stackexchange.com/questions/48935/why-use-argon2i-or-argon2d-if-argon2id-exists
func Encrypt(password []byte) (string, error) {
	return encrypt(password, parallelism, saltLen, time, memory, keyLen)
}

// Compare attempts to compare the password with the hash in constant-time compare.
func Compare(phc string, password []byte) (bool, error) {
	return compare(password, phc, keyLen)
}

// ConstantTimeCompare compares two strings in constant time.
func ConstantTimeCompare(s1, s2 string) bool {
	return subtle.ConstantTimeCompare([]byte(s1), []byte(s2)) == 1
}

// -- helper functions

func encrypt(password []byte, parallelism uint8, saltLen, time, memory, keyLen uint32) (string, error) {
	password = normalize(password)

	// Count the length of the runes
	if len([]rune(string(password))) == 0 {
		return "", ErrPasswordRequired
	}

	salt, err := generateSalt(saltLen)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrGenerateSalt, err)
	}

	unencodedHash := argon2.IDKey(password, []byte(salt), time, memory, parallelism, keyLen)
	encodedHash := base64.StdEncoding.EncodeToString(unencodedHash)
	phc := fmt.Sprintf("$%s$m=%d,t=%d,p=%d$%s$%s", id, memory, time, parallelism, salt, encodedHash)

	return phc, nil
}

func compare(password []byte, phc string, keyLen uint32) (bool, error) {
	password = normalize(password)

	phc = strings.TrimSpace(phc)
	if len([]rune(string(password))) == 0 || len(phc) == 0 {
		return false, ErrPasswordRequired
	}

	parts := strings.Split(phc[1:], "$")
	if len(parts) != hashPartsLen {
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
		return false, fmt.Errorf("%w: %s", ErrBase64Decode, err)
	}

	var m, t uint32
	var p uint8
	n, err := fmt.Sscanf(params, "m=%d,t=%d,p=%d", &m, &t, &p)
	if n != scanArgsLen {
		return false, fmt.Errorf("%w: %s", ErrHashInvalid, err)
	}

	computedHash := argon2.IDKey(password, []byte(salt), t, m, p, keyLen)
	if subtle.ConstantTimeCompare(hash, computedHash) != 1 {
		return false, nil
	}

	return true, nil
}

// Normalize password. Some devices uses different normalization standard,
// hence login in with the same password on those device might lead to
// mismatched password. We use NFKC because due to decomposition in NFKD, the
// length appears to be longer (see TestNormalizationLength)
func normalize(b []byte) []byte {
	return norm.NFKC.Bytes(b)
}
