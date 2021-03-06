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
