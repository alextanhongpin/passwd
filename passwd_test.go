package passwd_test

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/alextanhongpin/passwd"
	"golang.org/x/text/unicode/norm"

	"github.com/stretchr/testify/assert"
)

func ExampleEncrypt() {
	password := "your raw text password"
	hash, err := passwd.Encrypt(password)
	if err != nil {
		panic(err)
	}
	log.Println(hash)
}

func ExampleCompare() {
	hash := "$argon2id$v=19$m=65536,t=2,p=4$Sw8vppzw93YpLPotOuQhAA==$1uIAcD43cWZB5AxXI+zMUx6e2zzMaAJL2F1rAF0MX88="
	password := "secret"
	err := passwd.Compare(hash, password)
	fmt.Println(err)
	// Output:
	// <nil>
}

func ExampleArgon2id_Encrypt() {
	password := "your raw text password"
	hasher := passwd.New()
	hash, err := hasher.Encrypt(password)
	fmt.Println(err)

	err = hasher.Compare(hash, password)
	fmt.Println(err)

	err = hasher.Compare(hash, "wrong password")
	fmt.Println(err)
	// Output:
	// <nil>
	// <nil>
	// passwd: wrong password
}

func TestPasswordHashAndCompare(t *testing.T) {
	is := assert.New(t)

	password := "secret"
	hash, err := passwd.Encrypt(password)
	is.Nil(err)
	is.Nil(passwd.Compare(hash, password))

	t.Log(hash)
}

func TestCompare(t *testing.T) {
	test := func(name string, phc, password string, err error) {
		t.Run(name, func(t *testing.T) {
			is := assert.New(t)
			is.ErrorIs(passwd.Compare(phc, password), err)
		})
	}
	test("empty phc", "", "x", passwd.ErrInvalidHash)
	test("empty password", "x", "", passwd.ErrEmptyPassword)
	test("invalid hash", "x", "x", passwd.ErrInvalidHash)
}

func TestNormalization(t *testing.T) {
	// latin small letter e with acute (1234567\u00e9)
	password1 := "1234567é"

	// latin small letter e followed by combining acute accent (1234567\u0065\u0301)
	password2 := "1234567é"

	t.Run("equality before normalization", func(t *testing.T) {
		is := assert.New(t)
		is.False(password1 == password2)
	})

	t.Run("equality after normalization", func(t *testing.T) {
		nfkc1 := norm.NFKC.Bytes([]byte(password1))
		nfkc2 := norm.NFKC.Bytes([]byte(password2))

		is := assert.New(t)
		is.True(bytes.Equal(nfkc1, nfkc2))
	})

	t.Run("normalized encryption", func(t *testing.T) {
		hash, err := passwd.Encrypt(password1)
		is := assert.New(t)
		is.Nil(err)

		is.Nil(passwd.Compare(hash, password2))
	})
}

func TestNormalizationLength(t *testing.T) {
	b := []byte("1234567é")
	nfc := norm.NFC.Bytes(b)
	nfd := norm.NFD.Bytes(b)
	nfkc := norm.NFKC.Bytes(b)
	nfkd := norm.NFKD.Bytes(b)

	is := assert.New(t)
	is.Equal(len(nfc), 9)
	is.Equal(len(nfd), 10)
	is.Equal(len(nfkc), 9)
	is.Equal(len(nfkd), 10)

	runelen := func(b []byte) int {
		// Using `len([]rune(string(b)))` is now as optimized as using `utf8.RuneCountInString(string(b))`
		//
		// Reference:
		// https://stackoverflow.com/questions/12668681/how-to-get-the-number-of-characters-in-a-string
		return len([]rune(string(b)))
	}

	is.Equal(runelen(nfc), 8)
	is.Equal(runelen(nfd), 9)
	is.Equal(runelen(nfkc), 8)
	is.Equal(runelen(nfkd), 9)
}

func TestArgon2id_Validate(t *testing.T) {
	tests := []struct {
		name    string
		hasher  *passwd.Argon2id
		wantErr bool
	}{
		{
			name:    "valid parameters",
			hasher:  passwd.New(),
			wantErr: false,
		},
		{
			name: "invalid time",
			hasher: &passwd.Argon2id{
				Time:        0,
				Memory:      64 * 1024,
				Parallelism: 4,
				KeyLen:      32,
				SaltLen:     16,
			},
			wantErr: true,
		},
		{
			name: "invalid memory",
			hasher: &passwd.Argon2id{
				Time:        2,
				Memory:      500,
				Parallelism: 4,
				KeyLen:      32,
				SaltLen:     16,
			},
			wantErr: true,
		},
		{
			name: "invalid parallelism",
			hasher: &passwd.Argon2id{
				Time:        2,
				Memory:      64 * 1024,
				Parallelism: 0,
				KeyLen:      32,
				SaltLen:     16,
			},
			wantErr: true,
		},
		{
			name: "invalid key length",
			hasher: &passwd.Argon2id{
				Time:        2,
				Memory:      64 * 1024,
				Parallelism: 4,
				KeyLen:      8,
				SaltLen:     16,
			},
			wantErr: true,
		},
		{
			name: "invalid salt length",
			hasher: &passwd.Argon2id{
				Time:        2,
				Memory:      64 * 1024,
				Parallelism: 4,
				KeyLen:      32,
				SaltLen:     8,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.hasher.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestArgon2id_Hash(t *testing.T) {
	hasher := passwd.New()
	salt := make([]byte, 16)

	// Create a deterministic salt for testing
	for i := range salt {
		salt[i] = byte(i)
	}

	hash1, err := hasher.Hash("password", salt)
	assert.NoError(t, err)

	hash2, err := hasher.Hash("password", salt)
	assert.NoError(t, err)

	// Same password and salt should produce the same hash
	assert.Equal(t, hash1, hash2)

	// Test with wrong salt length
	wrongSalt := make([]byte, 10)
	_, err = hasher.Hash("password", wrongSalt)
	assert.Error(t, err)
}

func TestParse(t *testing.T) {
	// Test with valid hash
	validHash := "$argon2id$v=19$m=65536,t=2,p=4$Sw8vppzw93YpLPotOuQhAA==$1uIAcD43cWZB5AxXI+zMUx6e2zzMaAJL2F1rAF0MX88="
	result, err := passwd.Parse(validHash)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, uint32(65536), result.Argon2id.Memory)
	assert.Equal(t, uint32(2), result.Argon2id.Time)
	assert.Equal(t, uint8(4), result.Argon2id.Parallelism)

	// Test with invalid hash
	invalidHash := "invalid-hash"
	_, err = passwd.Parse(invalidHash)
	assert.Error(t, err)
}

func TestEdgeCases(t *testing.T) {
	t.Run("empty password", func(t *testing.T) {
		_, err := passwd.Encrypt("")
		assert.ErrorIs(t, err, passwd.ErrEmptyPassword)
	})

	t.Run("unicode password", func(t *testing.T) {
		password := "🔒🔑密码"
		hash, err := passwd.Encrypt(password)
		assert.NoError(t, err)
		assert.NoError(t, passwd.Compare(hash, password))
	})

	t.Run("very long password", func(t *testing.T) {
		password := strings.Repeat("a", 1000)
		hash, err := passwd.Encrypt(password)
		assert.NoError(t, err)
		assert.NoError(t, passwd.Compare(hash, password))
	})
}

func TestNeedsRehash(t *testing.T) {
	password := "testpassword"
	hash, err := passwd.Encrypt(password)
	assert.NoError(t, err)

	// Same parameters should not need rehash
	assert.False(t, passwd.NeedsRehash(hash))

	// Different parameters should need rehash
	customHasher := passwd.New().WithParams(1, 32*1024, 2, 32, 16)
	customHash, err := customHasher.Encrypt(password)
	assert.NoError(t, err)

	assert.True(t, passwd.NeedsRehash(customHash))

	// Invalid hash should need rehash
	assert.True(t, passwd.NeedsRehash("invalid-hash"))
}

func TestArgon2id_NeedsRehash(t *testing.T) {
	password := "testpassword"
	hasher := passwd.New().WithParams(1, 32*1024, 2, 32, 16)
	hash, err := hasher.Encrypt(password)
	assert.NoError(t, err)

	// Same parameters should not need rehash
	assert.False(t, hasher.NeedsRehash(hash))

	// Different parameters should need rehash
	differentHasher := passwd.New().WithParams(2, 64*1024, 4, 32, 16)
	assert.True(t, differentHasher.NeedsRehash(hash))

	// Invalid hash should need rehash
	assert.True(t, hasher.NeedsRehash("invalid-hash"))
}

func TestNewWithParams(t *testing.T) {
	hasher := passwd.New().WithParams(1, 32*1024, 2, 32, 16)
	assert.Equal(t, uint32(1), hasher.Time)
	assert.Equal(t, uint32(32*1024), hasher.Memory)
	assert.Equal(t, uint8(2), hasher.Parallelism)
	assert.Equal(t, uint32(32), hasher.KeyLen)
	assert.Equal(t, uint32(16), hasher.SaltLen)
}
