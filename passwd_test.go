package passwd_test

import (
	"bytes"
	"errors"
	"log"
	"testing"

	"github.com/alextanhongpin/passwd"
	"golang.org/x/text/unicode/norm"

	"github.com/stretchr/testify/assert"
)

func ExampleEncrypt() {
	password := []byte("your raw text password")
	hash, err := passwd.Encrypt(password)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(hash)
}

func ExampleCompare() {
	password := []byte("your raw text password")
	hash, _ := passwd.Encrypt(password)
	match, err := passwd.Compare(hash, password)
	if err != nil {
		log.Fatal(err)
	}
	if match != true {
		log.Fatal("password do not match")
	}
}

func TestPasswordHashAndCompare(t *testing.T) {
	assert := assert.New(t)

	var (
		password = []byte("secret")
	)
	hash, err := passwd.Encrypt(password)
	log.Println(hash)
	assert.Nil(err)

	match, err := passwd.Compare(hash, password)
	assert.Nil(err)
	assert.True(match)
}

func TestEmptyPassword(t *testing.T) {
	assert := assert.New(t)

	_, err := passwd.Encrypt([]byte(""))
	assert.NotNil(err)
	assert.True(errors.Is(err, passwd.ErrPasswordRequired))
}

func TestCompare(t *testing.T) {
	assert := assert.New(t)
	match, err := passwd.Compare("", nil)
	assert.NotNil(err)
	assert.True(errors.Is(err, passwd.ErrPasswordRequired))
	assert.False(match)

	match, err = passwd.Compare("", []byte("x"))
	assert.NotNil(err)
	assert.True(errors.Is(err, passwd.ErrPasswordRequired))
	assert.False(match)

	match, err = passwd.Compare("x", nil)
	assert.NotNil(err)
	assert.True(errors.Is(err, passwd.ErrPasswordRequired))
	assert.False(match)

	match, err = passwd.Compare("x", []byte("x"))
	assert.NotNil(err)
	assert.True(errors.Is(err, passwd.ErrHashInvalid))
	assert.False(match)

	match, err = passwd.Compare("$a$b$c$d", []byte("x"))
	assert.NotNil(err)
	assert.True(errors.Is(err, passwd.ErrUnknownHashFunction))
	assert.False(match)

	match, err = passwd.Compare("$argon2id$b$c$d", []byte("x"))
	assert.NotNil(err)
	assert.True(errors.Is(err, passwd.ErrBase64Decode))
	assert.False(match)
}

func TestNormalization(t *testing.T) {
	// latin small letter e with acute (1234567\u00e9)
	password1 := "1234567é"

	// latin small letter e followed by combining acute accent (1234567\u0065\u0301)
	password2 := "1234567é"

	assert := assert.New(t)

	t.Run("equality before normalization", func(t *testing.T) {
		t.Parallel()

		assert.False(password1 == password2)
	})

	t.Run("equality after normalization", func(t *testing.T) {
		t.Parallel()

		nfkc1 := norm.NFKC.Bytes([]byte(password1))
		nfkc2 := norm.NFKC.Bytes([]byte(password2))

		assert.True(bytes.Equal(nfkc1, nfkc2))
	})

	t.Run("normalized encryption", func(t *testing.T) {
		t.Parallel()

		hash, err := passwd.Encrypt([]byte(password1))
		assert.Nil(err)

		match, err := passwd.Compare(hash, []byte(password2))
		assert.Nil(err)
		assert.True(match)
	})
}

func TestNormalizationLength(t *testing.T) {
	assert := assert.New(t)

	b := []byte("1234567é")
	nfc := norm.NFC.Bytes(b)
	nfd := norm.NFD.Bytes(b)
	nfkc := norm.NFKC.Bytes(b)
	nfkd := norm.NFKD.Bytes(b)

	assert.Equal(len(nfc), 9)
	assert.Equal(len(nfd), 10)
	assert.Equal(len(nfkc), 9)
	assert.Equal(len(nfkd), 10)

	runelen := func(b []byte) int {
		// Using `len([]rune(string(b)))` is now as optimized as using `utf8.RuneCountInString(string(b))`
		//
		// Reference:
		// https://stackoverflow.com/questions/12668681/how-to-get-the-number-of-characters-in-a-string
		return len([]rune(string(b)))
	}

	assert.Equal(runelen(nfc), 8)
	assert.Equal(runelen(nfd), 9)
	assert.Equal(runelen(nfkc), 8)
	assert.Equal(runelen(nfkd), 9)
}
