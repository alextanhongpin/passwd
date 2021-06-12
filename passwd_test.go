package passwd_test

import (
	"log"
	"testing"

	"github.com/alextanhongpin/passwd"

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
}

func TestCompare(t *testing.T) {
	assert := assert.New(t)
	match, err := passwd.Compare("", nil)
	assert.NotNil(err)
	assert.Equal(err, passwd.ErrPasswordRequired)
	assert.False(match)

	match, err = passwd.Compare("", []byte("x"))
	assert.NotNil(err)
	assert.Equal(err, passwd.ErrPasswordRequired)
	assert.False(match)

	match, err = passwd.Compare("x", nil)
	assert.NotNil(err)
	assert.Equal(err, passwd.ErrPasswordRequired)
	assert.False(match)

	match, err = passwd.Compare("x", []byte("x"))
	assert.NotNil(err)
	assert.Equal(err, passwd.ErrHashInvalid)
	assert.False(match)

	match, err = passwd.Compare("$a$b$c$d", []byte("x"))
	assert.NotNil(err)
	assert.Equal("unknown password hashing function identifier", err.Error())
	assert.False(match)

	match, err = passwd.Compare("$argon2id$b$c$d", []byte("x"))
	assert.NotNil(err)
	assert.Equal("illegal base64 data at input byte 0", err.Error())
	assert.False(match)
}

func TestNormalization(t *testing.T) {
	// latin small letter e with acute
	password1 := "1234567\u00e9"

	// latin small letter e followed by combining acute accent
	password2 := "1234567\u0065\u0301"

	hash, err := passwd.Encrypt([]byte(password1))
	assert := assert.New(t)
	assert.Nil(err)

	match, err := passwd.Compare(hash, []byte(password2))
	assert.Nil(err)
	assert.True(match)
}
