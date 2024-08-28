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
	ErrDecodeBase64  = errors.New("passwd: error decoding base64")
	ErrEmptyPassword = errors.New("passwd: password must not be empty")
	ErrGenerateSalt  = errors.New("passwd: error generating salt")
	ErrInvalidHash   = errors.New("passwd: invalid argon2id hash")
	ErrWrongPassword = errors.New("passwd: wrong password")
)

// Argon2id contains the configuration for the argon2id hashing function.
type Argon2id struct {
	Time        uint32
	Memory      uint32
	Parallelism uint8
	KeyLen      uint32
	SaltLen     uint32
}

// New returns a new argon2id hasher with recommended options.
func New() Argon2id {
	return Argon2id{
		Time:        2,
		Memory:      64 * 1024,
		Parallelism: 4,
		KeyLen:      32,
		SaltLen:     16,
	}
}

// Encrypt hashes a raw-text password and return the hashed password.
func (a *Argon2id) Encrypt(password string) (string, error) {
	salt, err := generateSalt(a.SaltLen)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrGenerateSalt, err)
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

// Encrypt takes a password and return a encodedHash-formatted hash. PHC stands for password hashing competition.
//
// Reference:
// https://github.com/P-H-C/encodedHash-string-format/blob/master/encodedHash-sf-spec.md
// https://crypto.stackexchange.com/questions/48935/why-use-argon2i-or-argon2d-if-argon2id-exists
var argon2id = New()

func Encrypt(password string) (string, error) {
	return argon2id.Encrypt(password)
}

// Compare attempts to compare the password with the hash in constant-time compare.
func Compare(encodedHash, password string) error {
	return argon2id.Compare(encodedHash, password)
}

// Normalize password. Some devices uses different normalization standard,
// hence login in with the same password on those device might lead to
// mismatched password. We use NFKC because due to decomposition in NFKD, the
// length appears to be longer (see TestNormalizationLength)
func normalize(b []byte) []byte {
	return norm.NFKC.Bytes(b)
}

func runeLength(s string) int {
	return utf8.RuneCountInString(s)
}

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

type Result struct {
	Argon2id *Argon2id
	Hash     []byte
	Salt     []byte
}
