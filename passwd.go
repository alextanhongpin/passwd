// Package passwd provides secure password hashing using Argon2id algorithm.
//
// Argon2id is the winner of the Password Hashing Competition in 2015 and is
// recommended as a replacement for bcrypt. It provides better security against
// both side-channel and GPU cracking attacks.
//
// Basic usage:
//
//	hash, err := passwd.Encrypt("mysecret")
//	if err != nil {
//		// handle error
//	}
//
//	err = passwd.Compare(hash, "mysecret")
//	if err != nil {
//		// handle error
//	}
//
// For custom parameters:
//
//	hasher := passwd.New()
//	hasher.Time = 1
//	hasher.Memory = 32 * 1024
//	hash, err := hasher.Encrypt("mysecret")
package passwd

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

var (
	// ErrDecodeBase64 is returned when base64 decoding fails
	ErrDecodeBase64 = errors.New("passwd: error decoding base64")
	// ErrEmptyPassword is returned when password is empty
	ErrEmptyPassword = errors.New("passwd: password must not be empty")
	// ErrGenerateSalt is returned when salt generation fails
	ErrGenerateSalt = errors.New("passwd: error generating salt")
	// ErrInvalidHash is returned when hash format is invalid
	ErrInvalidHash = errors.New("passwd: invalid argon2id hash")
	// ErrWrongPassword is returned when password verification fails
	ErrWrongPassword = errors.New("passwd: wrong password")
	// ErrInvalidParameters is returned when argon2id parameters are invalid
	ErrInvalidParameters = errors.New("passwd: invalid parameters")
)

// Argon2id contains the configuration for the argon2id hashing function.
// Time: number of iterations
// Memory: memory usage in KB
// Parallelism: number of parallel threads
// KeyLen: length of the derived key in bytes
// SaltLen: length of the salt in bytes
type Argon2id struct {
	Time        uint32
	Memory      uint32
	Parallelism uint8
	KeyLen      uint32
	SaltLen     uint32
}

// New returns a new argon2id hasher with recommended options.
func New() *Argon2id {
	return &Argon2id{
		Time:        2,
		Memory:      64 * 1024,
		Parallelism: 4,
		KeyLen:      32,
		SaltLen:     16,
	}
}

// WithParams creates a new Argon2id hasher with custom parameters.
// This is a convenience function for creating a hasher with specific settings.
func (a *Argon2id) WithParams(time, memory uint32, parallelism uint8, keyLen, saltLen uint32) *Argon2id {
	return &Argon2id{
		Time:        time,
		Memory:      memory,
		Parallelism: parallelism,
		KeyLen:      keyLen,
		SaltLen:     saltLen,
	}
}

// Validate checks if the Argon2id parameters are valid and secure.
func (a *Argon2id) Validate() error {
	if a.Time < 1 {
		return fmt.Errorf("%w: time must be at least 1", ErrInvalidParameters)
	}
	if a.Memory < 1024 {
		return fmt.Errorf("%w: memory must be at least 1024 KB", ErrInvalidParameters)
	}
	if a.Parallelism < 1 {
		return fmt.Errorf("%w: parallelism must be at least 1", ErrInvalidParameters)
	}
	if a.KeyLen < 16 {
		return fmt.Errorf("%w: key length must be at least 16 bytes", ErrInvalidParameters)
	}
	if a.SaltLen < 16 {
		return fmt.Errorf("%w: salt length must be at least 16 bytes", ErrInvalidParameters)
	}
	return nil
}

// Encrypt hashes a raw-text password and return the hashed password.
func (a *Argon2id) Encrypt(password string) (string, error) {
	if err := a.Validate(); err != nil {
		return "", err
	}

	salt, err := generateSalt(a.SaltLen)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrGenerateSalt, err)
	}

	return a.encryptWithSalt([]byte(password), salt)
}

// Hash creates a hash for the given password using provided salt.
// This is useful for testing or when you need deterministic hashing.
func (a *Argon2id) Hash(password string, salt []byte) (string, error) {
	if err := a.Validate(); err != nil {
		return "", err
	}

	if len(salt) != int(a.SaltLen) {
		return "", fmt.Errorf("%w: salt length must be %d bytes", ErrInvalidParameters, a.SaltLen)
	}

	return a.encryptWithSalt([]byte(password), salt)
}

// Compare attempts to compare the password with the hash in constant-time compare.
func (a *Argon2id) Compare(encodedHash, password string) error {
	if runeLength(password) == 0 {
		return ErrEmptyPassword
	}
	if runeLength(encodedHash) == 0 {
		return fmt.Errorf("%w: hash is empty", ErrInvalidHash)
	}

	r, err := Parse(encodedHash)
	if err != nil {
		return err
	}

	h, err := r.Argon2id.encryptWithSalt([]byte(password), r.Salt)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(encodedHash), []byte(h)) != 1 {
		return ErrWrongPassword
	}

	return nil
}

func (a *Argon2id) encryptWithSalt(password, salt []byte) (string, error) {
	password = normalize(password)

	// Count the length of the runes
	if runeLength(string(password)) == 0 {
		return "", ErrEmptyPassword
	}

	hash := argon2.IDKey(password, salt, a.Time, a.Memory, a.Parallelism, a.KeyLen)
	b64Salt := base64.StdEncoding.EncodeToString(salt)
	b64Hash := base64.StdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, a.Memory, a.Time, a.Parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

func generateSalt(size uint32) ([]byte, error) {
	salt := make([]byte, size)

	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	return salt, nil
}

// Encrypt takes a password and return a hash-formatted string using PHC format.
// PHC stands for Password Hashing Competition.
//
// Reference:
// https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
// https://crypto.stackexchange.com/questions/48935/why-use-argon2i-or-argon2d-if-argon2id-exists
var defaultHasher = New()

// Encrypt hashes a password using the default Argon2id configuration.
func Encrypt(password string) (string, error) {
	return defaultHasher.Encrypt(password)
}

// Compare verifies if the given password matches the hash using constant-time comparison.
func Compare(hash, password string) error {
	return defaultHasher.Compare(hash, password)
}

// NeedsRehash checks if a hash needs to be rehashed with the current default parameters.
// This is useful for upgrading password hashes when you change your security parameters.
func NeedsRehash(hash string) bool {
	result, err := Parse(hash)
	if err != nil {
		return true // Invalid hash should be rehashed
	}

	current := New()
	return result.Argon2id.Time != current.Time ||
		result.Argon2id.Memory != current.Memory ||
		result.Argon2id.Parallelism != current.Parallelism ||
		result.Argon2id.KeyLen != current.KeyLen ||
		result.Argon2id.SaltLen != current.SaltLen
}

// NeedsRehash checks if a hash needs to be rehashed with this hasher's parameters.
func (a *Argon2id) NeedsRehash(hash string) bool {
	result, err := Parse(hash)
	if err != nil {
		return true // Invalid hash should be rehashed
	}

	return result.Argon2id.Time != a.Time ||
		result.Argon2id.Memory != a.Memory ||
		result.Argon2id.Parallelism != a.Parallelism ||
		result.Argon2id.KeyLen != a.KeyLen ||
		result.Argon2id.SaltLen != a.SaltLen
}

// normalize normalizes the password using NFKC normalization.
// Some devices use different normalization standards, so normalizing
// helps ensure consistent password matching across different devices.
// We use NFKC because it provides better compatibility than NFKD.
func normalize(b []byte) []byte {
	return norm.NFKC.Bytes(b)
}

// runeLength returns the number of UTF-8 runes in the string.
func runeLength(s string) int {
	return utf8.RuneCountInString(s)
}

// Parse parses an Argon2id hash string and returns the components.
func Parse(s string) (*Result, error) {
	var version int
	var b64SaltPlusHash string
	var a Argon2id
	n, err := fmt.Sscanf(s, "$argon2id$v=%d$m=%d,t=%d,p=%d$%s", &version, &a.Memory, &a.Time, &a.Parallelism, &b64SaltPlusHash)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidHash, err)
	}
	if n != 5 || version != argon2.Version {
		return nil, ErrInvalidHash
	}

	b64Salt, b64Hash, ok := strings.Cut(b64SaltPlusHash, "$")
	if !ok {
		return nil, ErrInvalidHash
	}

	salt, err := base64.StdEncoding.DecodeString(b64Salt)
	if err != nil {
		return nil, fmt.Errorf("%w: salt: %w", ErrDecodeBase64, err)
	}
	a.SaltLen = uint32(len(salt))

	hash, err := base64.StdEncoding.DecodeString(b64Hash)
	if err != nil {
		return nil, fmt.Errorf("%w: hash: %w", ErrDecodeBase64, err)
	}
	a.KeyLen = uint32(len(hash))

	return &Result{
		Argon2id: &a,
		Hash:     hash,
		Salt:     salt,
	}, nil
}

// Result represents the parsed components of an Argon2id hash.
type Result struct {
	Argon2id *Argon2id
	Hash     []byte
	Salt     []byte
}
